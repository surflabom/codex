use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::fmt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use codex_protocol::ThreadId;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value as JsonValue;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::process::Child;
use tokio::process::ChildStdin;
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::sync::OnceCell;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use uuid::Uuid;

use crate::client_common::tools::ToolSpec;
use crate::codex::Session;
use crate::codex::TurnContext;
use crate::exec::ExecExpiration;
use crate::exec_env::create_env;
use crate::function_tool::FunctionCallError;
use crate::sandboxing::CommandSpec;
use crate::sandboxing::SandboxManager;
use crate::sandboxing::SandboxPermissions;
use crate::tools::ToolRouter;
use crate::tools::context::SharedTurnDiffTracker;
use crate::tools::sandboxing::SandboxablePreference;

pub(crate) const JS_REPL_PRAGMA_PREFIX: &str = "// codex-js-repl:";
const KERNEL_SOURCE: &str = include_str!("kernel.js");
const MERIYAH_UMD: &str = include_str!("meriyah.umd.min.js");
const JS_REPL_MIN_NODE_VERSION: &str = include_str!("../../../../node-version.txt");
const JS_REPL_POLL_MIN_MS: u64 = 50;
const JS_REPL_POLL_MAX_MS: u64 = 5_000;
const JS_REPL_POLL_DEFAULT_MS: u64 = 1_000;

/// Per-task js_repl handle stored on the turn context.
pub(crate) struct JsReplHandle {
    node_path: Option<PathBuf>,
    codex_home: PathBuf,
    cell: OnceCell<Arc<JsReplManager>>,
}

impl fmt::Debug for JsReplHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsReplHandle").finish_non_exhaustive()
    }
}

impl JsReplHandle {
    pub(crate) fn with_node_path(node_path: Option<PathBuf>, codex_home: PathBuf) -> Self {
        Self {
            node_path,
            codex_home,
            cell: OnceCell::new(),
        }
    }

    pub(crate) async fn manager(&self) -> Result<Arc<JsReplManager>, FunctionCallError> {
        self.cell
            .get_or_try_init(|| async {
                JsReplManager::new(self.node_path.clone(), self.codex_home.clone()).await
            })
            .await
            .cloned()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsReplArgs {
    pub code: String,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub poll: bool,
}

#[derive(Clone, Debug)]
pub struct JsExecResult {
    pub output: String,
}

#[derive(Clone, Debug)]
pub struct JsExecSubmission {
    pub exec_id: String,
}

#[derive(Clone, Debug)]
pub struct JsExecPollResult {
    pub exec_id: String,
    pub event_call_id: String,
    pub logs: Vec<String>,
    pub all_logs: Vec<String>,
    pub output: Option<String>,
    pub error: Option<String>,
    pub done: bool,
    pub duration: Option<Duration>,
}

struct KernelState {
    _child: Child,
    stdin: Arc<Mutex<ChildStdin>>,
    pending_execs: Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<ExecResultMessage>>>>,
    exec_contexts: Arc<Mutex<HashMap<String, ExecContext>>>,
    shutdown: CancellationToken,
}

#[derive(Clone)]
struct ExecContext {
    session: Arc<Session>,
    turn: Arc<TurnContext>,
    tracker: SharedTurnDiffTracker,
}

#[derive(Default)]
struct ExecToolCalls {
    in_flight: usize,
    notify: Arc<Notify>,
}

struct ExecBuffer {
    event_call_id: String,
    logs: VecDeque<String>,
    all_logs: Vec<String>,
    output: Option<String>,
    error: Option<String>,
    done: bool,
    started_at: Instant,
    notify: Arc<Notify>,
}

impl ExecBuffer {
    fn new(event_call_id: String) -> Self {
        Self {
            event_call_id,
            logs: VecDeque::new(),
            all_logs: Vec::new(),
            output: None,
            error: None,
            done: false,
            started_at: Instant::now(),
            notify: Arc::new(Notify::new()),
        }
    }
}

pub struct JsReplManager {
    node_path: Option<PathBuf>,
    js_repl_home: PathBuf,
    vendor_node_modules: PathBuf,
    user_node_modules: PathBuf,
    npm_config_path: PathBuf,
    npm_cache_dir: PathBuf,
    npm_tmp_dir: PathBuf,
    npm_prefix_dir: PathBuf,
    xdg_config_dir: PathBuf,
    xdg_cache_dir: PathBuf,
    xdg_data_dir: PathBuf,
    yarn_cache_dir: PathBuf,
    pnpm_store_dir: PathBuf,
    corepack_home: PathBuf,
    tmp_dir: tempfile::TempDir,
    kernel: Mutex<Option<KernelState>>,
    exec_lock: Arc<Semaphore>,
    exec_tool_calls: Arc<Mutex<HashMap<String, ExecToolCalls>>>,
    exec_store: Arc<Mutex<HashMap<String, ExecBuffer>>>,
    poll_kernels: Arc<Mutex<HashMap<String, KernelState>>>,
}

impl JsReplManager {
    async fn new(
        node_path: Option<PathBuf>,
        codex_home: PathBuf,
    ) -> Result<Arc<Self>, FunctionCallError> {
        let js_repl_home = codex_home.join("js_repl");
        let tmp_dir = tempfile::tempdir().map_err(|err| {
            FunctionCallError::RespondToModel(format!("failed to create js_repl temp dir: {err}"))
        })?;
        let (
            vendor_node_modules,
            user_node_modules,
            npm_config_path,
            npm_cache_dir,
            npm_tmp_dir,
            npm_prefix_dir,
            xdg_config_dir,
            xdg_cache_dir,
            xdg_data_dir,
            yarn_cache_dir,
            pnpm_store_dir,
            corepack_home,
        ) = prepare_js_repl_home(&js_repl_home).await.map_err(|err| {
            FunctionCallError::RespondToModel(format!("failed to prepare js_repl home: {err}"))
        })?;

        let manager = Arc::new(Self {
            node_path,
            js_repl_home,
            vendor_node_modules,
            user_node_modules,
            npm_config_path,
            npm_cache_dir,
            npm_tmp_dir,
            npm_prefix_dir,
            xdg_config_dir,
            xdg_cache_dir,
            xdg_data_dir,
            yarn_cache_dir,
            pnpm_store_dir,
            corepack_home,
            tmp_dir,
            kernel: Mutex::new(None),
            exec_lock: Arc::new(Semaphore::new(1)),
            exec_tool_calls: Arc::new(Mutex::new(HashMap::new())),
            exec_store: Arc::new(Mutex::new(HashMap::new())),
            poll_kernels: Arc::new(Mutex::new(HashMap::new())),
        });

        Ok(manager)
    }

    async fn register_exec_tool_calls(&self, exec_id: &str) {
        self.exec_tool_calls
            .lock()
            .await
            .insert(exec_id.to_string(), ExecToolCalls::default());
    }

    async fn clear_exec_tool_calls(&self, exec_id: &str) {
        if let Some(state) = self.exec_tool_calls.lock().await.remove(exec_id) {
            state.notify.notify_waiters();
        }
    }

    async fn wait_for_exec_tool_calls(&self, exec_id: &str) {
        loop {
            let notify = {
                let calls = self.exec_tool_calls.lock().await;
                calls
                    .get(exec_id)
                    .filter(|state| state.in_flight > 0)
                    .map(|state| Arc::clone(&state.notify))
            };
            match notify {
                Some(notify) => notify.notified().await,
                None => return,
            }
        }
    }

    async fn wait_for_all_exec_tool_calls(&self) {
        loop {
            let notify = {
                let calls = self.exec_tool_calls.lock().await;
                calls
                    .values()
                    .find(|state| state.in_flight > 0)
                    .map(|state| Arc::clone(&state.notify))
            };
            match notify {
                Some(notify) => notify.notified().await,
                None => return,
            }
        }
    }

    async fn begin_exec_tool_call(
        exec_tool_calls: &Arc<Mutex<HashMap<String, ExecToolCalls>>>,
        exec_id: &str,
    ) -> bool {
        let mut calls = exec_tool_calls.lock().await;
        let Some(state) = calls.get_mut(exec_id) else {
            return false;
        };
        state.in_flight += 1;
        true
    }

    async fn finish_exec_tool_call(
        exec_tool_calls: &Arc<Mutex<HashMap<String, ExecToolCalls>>>,
        exec_id: &str,
    ) {
        let notify = {
            let mut calls = exec_tool_calls.lock().await;
            let Some(state) = calls.get_mut(exec_id) else {
                return;
            };
            if state.in_flight == 0 {
                return;
            }
            state.in_flight -= 1;
            if state.in_flight == 0 {
                Some(Arc::clone(&state.notify))
            } else {
                None
            }
        };
        if let Some(notify) = notify {
            notify.notify_waiters();
        }
    }

    async fn wait_for_exec_tool_calls_map(
        exec_tool_calls: &Arc<Mutex<HashMap<String, ExecToolCalls>>>,
        exec_id: &str,
    ) {
        loop {
            let notify = {
                let calls = exec_tool_calls.lock().await;
                calls
                    .get(exec_id)
                    .filter(|state| state.in_flight > 0)
                    .map(|state| Arc::clone(&state.notify))
            };
            match notify {
                Some(notify) => notify.notified().await,
                None => return,
            }
        }
    }

    async fn clear_exec_tool_calls_map(
        exec_tool_calls: &Arc<Mutex<HashMap<String, ExecToolCalls>>>,
        exec_id: &str,
    ) {
        if let Some(state) = exec_tool_calls.lock().await.remove(exec_id) {
            state.notify.notify_waiters();
        }
    }

    pub async fn reset(&self) -> Result<(), FunctionCallError> {
        self.reset_kernel().await;
        self.reset_poll_kernels().await;
        self.wait_for_all_exec_tool_calls().await;
        self.exec_tool_calls.lock().await.clear();
        self.exec_store.lock().await.clear();
        Ok(())
    }

    async fn reset_kernel(&self) {
        let state = {
            let mut guard = self.kernel.lock().await;
            guard.take()
        };
        if let Some(state) = state {
            state.shutdown.cancel();
        }
    }

    async fn reset_poll_kernel(&self, exec_id: &str) {
        let state = self.poll_kernels.lock().await.remove(exec_id);
        if let Some(state) = state {
            state.shutdown.cancel();
        }
    }

    async fn reset_poll_kernels(&self) {
        let states = {
            let mut guard = self.poll_kernels.lock().await;
            guard.drain().map(|(_, state)| state).collect::<Vec<_>>()
        };
        for state in states {
            state.shutdown.cancel();
        }
    }

    pub async fn execute(
        &self,
        session: Arc<Session>,
        turn: Arc<TurnContext>,
        tracker: SharedTurnDiffTracker,
        args: JsReplArgs,
    ) -> Result<JsExecResult, FunctionCallError> {
        let _permit = self.exec_lock.clone().acquire_owned().await.map_err(|_| {
            FunctionCallError::RespondToModel("js_repl execution unavailable".to_string())
        })?;

        let (stdin, pending_execs, exec_contexts) = {
            let mut kernel = self.kernel.lock().await;
            if kernel.is_none() {
                let state = self
                    .start_kernel(Arc::clone(&turn), Some(session.conversation_id))
                    .await
                    .map_err(FunctionCallError::RespondToModel)?;
                *kernel = Some(state);
            }

            let state = match kernel.as_ref() {
                Some(state) => state,
                None => {
                    return Err(FunctionCallError::RespondToModel(
                        "js_repl kernel unavailable".to_string(),
                    ));
                }
            };
            (
                Arc::clone(&state.stdin),
                Arc::clone(&state.pending_execs),
                Arc::clone(&state.exec_contexts),
            )
        };

        let (req_id, rx) = {
            let req_id = Uuid::new_v4().to_string();
            let mut pending = pending_execs.lock().await;
            let (tx, rx) = tokio::sync::oneshot::channel();
            pending.insert(req_id.clone(), tx);
            exec_contexts.lock().await.insert(
                req_id.clone(),
                ExecContext {
                    session: Arc::clone(&session),
                    turn: Arc::clone(&turn),
                    tracker,
                },
            );
            (req_id, rx)
        };
        self.register_exec_tool_calls(&req_id).await;

        let payload = HostToKernel::Exec {
            id: req_id.clone(),
            code: args.code,
            timeout_ms: args.timeout_ms,
            stream_logs: false,
        };

        if let Err(err) = Self::write_message(&stdin, &payload).await {
            pending_execs.lock().await.remove(&req_id);
            exec_contexts.lock().await.remove(&req_id);
            self.clear_exec_tool_calls(&req_id).await;
            return Err(err);
        }

        let timeout_ms = args.timeout_ms.unwrap_or(30_000);
        let response = match tokio::time::timeout(Duration::from_millis(timeout_ms), rx).await {
            Ok(Ok(msg)) => msg,
            Ok(Err(_)) => {
                let mut pending = pending_execs.lock().await;
                pending.remove(&req_id);
                exec_contexts.lock().await.remove(&req_id);
                self.wait_for_exec_tool_calls(&req_id).await;
                self.clear_exec_tool_calls(&req_id).await;
                return Err(FunctionCallError::RespondToModel(
                    "js_repl kernel closed unexpectedly".to_string(),
                ));
            }
            Err(_) => {
                self.reset().await?;
                return Err(FunctionCallError::RespondToModel(
                    "js_repl execution timed out; kernel reset, rerun your request".to_string(),
                ));
            }
        };

        match response {
            ExecResultMessage::Ok { output } => Ok(JsExecResult { output }),
            ExecResultMessage::Err { message } => Err(FunctionCallError::RespondToModel(message)),
        }
    }

    pub async fn submit(
        self: Arc<Self>,
        session: Arc<Session>,
        turn: Arc<TurnContext>,
        tracker: SharedTurnDiffTracker,
        event_call_id: String,
        args: JsReplArgs,
    ) -> Result<JsExecSubmission, FunctionCallError> {
        let state = self
            .start_kernel(Arc::clone(&turn), Some(session.conversation_id))
            .await
            .map_err(FunctionCallError::RespondToModel)?;
        let exec_contexts = Arc::clone(&state.exec_contexts);
        let stdin = Arc::clone(&state.stdin);
        let shutdown = state.shutdown.clone();

        let req_id = Uuid::new_v4().to_string();
        exec_contexts.lock().await.insert(
            req_id.clone(),
            ExecContext {
                session: Arc::clone(&session),
                turn: Arc::clone(&turn),
                tracker,
            },
        );
        self.exec_store
            .lock()
            .await
            .insert(req_id.clone(), ExecBuffer::new(event_call_id));
        self.register_exec_tool_calls(&req_id).await;

        self.poll_kernels.lock().await.insert(req_id.clone(), state);

        let payload = HostToKernel::Exec {
            id: req_id.clone(),
            code: args.code,
            timeout_ms: args.timeout_ms,
            stream_logs: true,
        };
        if let Err(err) = Self::write_message(&stdin, &payload).await {
            self.exec_store.lock().await.remove(&req_id);
            exec_contexts.lock().await.remove(&req_id);
            self.poll_kernels.lock().await.remove(&req_id);
            self.clear_exec_tool_calls(&req_id).await;
            shutdown.cancel();
            return Err(err);
        }

        let timeout_ms = args.timeout_ms.unwrap_or(30_000);
        let manager = Arc::clone(&self);
        let timeout_exec_id = req_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(timeout_ms)).await;
            manager.reset_poll_kernel(&timeout_exec_id).await;
            manager.wait_for_exec_tool_calls(&timeout_exec_id).await;
            manager.mark_timed_out(&timeout_exec_id).await;
            manager.clear_exec_tool_calls(&timeout_exec_id).await;
        });

        Ok(JsExecSubmission { exec_id: req_id })
    }

    pub async fn poll(
        &self,
        exec_id: &str,
        yield_time_ms: Option<u64>,
    ) -> Result<JsExecPollResult, FunctionCallError> {
        let deadline = Instant::now() + Duration::from_millis(clamp_poll_ms(yield_time_ms));

        loop {
            let (notify, event_call_id, done, logs, all_logs, output, error, duration) = {
                let mut store = self.exec_store.lock().await;
                let Some(entry) = store.get_mut(exec_id) else {
                    return Err(FunctionCallError::RespondToModel(
                        "js_repl exec id not found".to_string(),
                    ));
                };
                if !entry.logs.is_empty() || entry.done {
                    let drained_logs: Vec<String> = entry.logs.drain(..).collect();
                    let event_call_id = entry.event_call_id.clone();
                    let output = entry.output.take();
                    let error = entry.error.take();
                    let done = entry.done;
                    let all_logs = if done {
                        entry.all_logs.clone()
                    } else {
                        Vec::new()
                    };
                    let duration = if done {
                        Some(entry.started_at.elapsed())
                    } else {
                        None
                    };
                    if done {
                        store.remove(exec_id);
                    }
                    return Ok(JsExecPollResult {
                        exec_id: exec_id.to_string(),
                        event_call_id,
                        logs: drained_logs,
                        all_logs,
                        output,
                        error,
                        done,
                        duration,
                    });
                }
                (
                    Arc::clone(&entry.notify),
                    entry.event_call_id.clone(),
                    entry.done,
                    Vec::new(),
                    Vec::new(),
                    None,
                    None,
                    None,
                )
            };

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(JsExecPollResult {
                    exec_id: exec_id.to_string(),
                    event_call_id,
                    logs,
                    all_logs,
                    output,
                    error,
                    done,
                    duration,
                });
            }

            if tokio::time::timeout(remaining, notify.notified())
                .await
                .is_err()
            {
                return Ok(JsExecPollResult {
                    exec_id: exec_id.to_string(),
                    event_call_id,
                    logs,
                    all_logs,
                    output,
                    error,
                    done,
                    duration,
                });
            }
        }
    }

    async fn mark_timed_out(&self, exec_id: &str) -> bool {
        let mut store = self.exec_store.lock().await;
        let Some(entry) = store.get_mut(exec_id) else {
            return false;
        };
        if entry.done {
            return false;
        }
        entry.done = true;
        entry.error =
            Some("js_repl execution timed out; kernel reset, rerun your request".to_string());
        entry.notify.notify_waiters();
        true
    }
    async fn start_kernel(
        &self,
        turn: Arc<TurnContext>,
        thread_id: Option<ThreadId>,
    ) -> Result<KernelState, String> {
        let node_path = resolve_node(self.node_path.as_deref()).ok_or_else(|| {
            "Node runtime not found; install Node or set CODEX_JS_REPL_NODE_PATH".to_string()
        })?;
        ensure_node_version(&node_path).await?;

        let kernel_path = self
            .write_kernel_script()
            .await
            .map_err(|err| err.to_string())?;

        let mut env = create_env(&turn.shell_environment_policy, thread_id);
        self.configure_js_repl_env(&mut env);

        let spec = CommandSpec {
            program: node_path.to_string_lossy().to_string(),
            args: vec![
                "--experimental-vm-modules".to_string(),
                kernel_path.to_string_lossy().to_string(),
            ],
            cwd: turn.cwd.clone(),
            env,
            expiration: ExecExpiration::DefaultTimeout,
            sandbox_permissions: SandboxPermissions::UseDefault,
            justification: None,
        };

        let sandbox = SandboxManager::new();
        let has_managed_network_requirements = turn
            .config
            .config_layer_stack
            .requirements_toml()
            .network
            .is_some();
        let sandbox_type = sandbox.select_initial(
            &turn.sandbox_policy,
            SandboxablePreference::Auto,
            turn.windows_sandbox_level,
            has_managed_network_requirements,
        );
        let exec_env = sandbox
            .transform(crate::sandboxing::SandboxTransformRequest {
                spec,
                policy: &turn.sandbox_policy,
                sandbox: sandbox_type,
                enforce_managed_network: has_managed_network_requirements,
                network: None,
                sandbox_policy_cwd: &turn.cwd,
                codex_linux_sandbox_exe: turn.codex_linux_sandbox_exe.as_ref(),
                use_linux_sandbox_bwrap: turn
                    .features
                    .enabled(crate::features::Feature::UseLinuxSandboxBwrap),
                windows_sandbox_level: turn.windows_sandbox_level,
            })
            .map_err(|err| format!("failed to configure sandbox for js_repl: {err}"))?;

        let mut cmd =
            tokio::process::Command::new(exec_env.command.first().cloned().unwrap_or_default());
        if exec_env.command.len() > 1 {
            cmd.args(&exec_env.command[1..]);
        }
        #[cfg(unix)]
        cmd.arg0(
            exec_env
                .arg0
                .clone()
                .unwrap_or_else(|| exec_env.command.first().cloned().unwrap_or_default()),
        );
        cmd.current_dir(&exec_env.cwd);
        cmd.env_clear();
        cmd.envs(exec_env.env);
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .map_err(|err| format!("failed to start Node runtime: {err}"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "js_repl kernel missing stdout".to_string())?;
        let stderr = child.stderr.take();
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "js_repl kernel missing stdin".to_string())?;

        let shutdown = CancellationToken::new();
        let pending_execs: Arc<
            Mutex<HashMap<String, tokio::sync::oneshot::Sender<ExecResultMessage>>>,
        > = Arc::new(Mutex::new(HashMap::new()));
        let exec_contexts: Arc<Mutex<HashMap<String, ExecContext>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let stdin_arc = Arc::new(Mutex::new(stdin));

        tokio::spawn(Self::read_stdout(
            stdout,
            Arc::clone(&pending_execs),
            Arc::clone(&exec_contexts),
            Arc::clone(&self.exec_tool_calls),
            Arc::clone(&self.exec_store),
            Arc::clone(&self.poll_kernels),
            Arc::clone(&stdin_arc),
            shutdown.clone(),
        ));
        if let Some(stderr) = stderr {
            tokio::spawn(Self::read_stderr(stderr, shutdown.clone()));
        } else {
            warn!("js_repl kernel missing stderr");
        }

        Ok(KernelState {
            _child: child,
            stdin: stdin_arc,
            pending_execs,
            exec_contexts,
            shutdown,
        })
    }

    async fn write_kernel_script(&self) -> Result<PathBuf, std::io::Error> {
        let dir = self.tmp_dir.path();
        let kernel_path = dir.join("js_repl_kernel.js");
        let meriyah_path = dir.join("meriyah.umd.min.js");
        tokio::fs::write(&kernel_path, KERNEL_SOURCE).await?;
        tokio::fs::write(&meriyah_path, MERIYAH_UMD).await?;
        Ok(kernel_path)
    }

    async fn write_message(
        stdin: &Arc<Mutex<ChildStdin>>,
        msg: &HostToKernel,
    ) -> Result<(), FunctionCallError> {
        let encoded = serde_json::to_string(msg).map_err(|err| {
            FunctionCallError::RespondToModel(format!("failed to serialize kernel message: {err}"))
        })?;
        let mut guard = stdin.lock().await;
        guard.write_all(encoded.as_bytes()).await.map_err(|err| {
            FunctionCallError::RespondToModel(format!("failed to write to kernel: {err}"))
        })?;
        guard.write_all(b"\n").await.map_err(|err| {
            FunctionCallError::RespondToModel(format!("failed to flush kernel message: {err}"))
        })?;
        Ok(())
    }

    async fn read_stdout(
        stdout: tokio::process::ChildStdout,
        pending_execs: Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<ExecResultMessage>>>>,
        exec_contexts: Arc<Mutex<HashMap<String, ExecContext>>>,
        exec_tool_calls: Arc<Mutex<HashMap<String, ExecToolCalls>>>,
        exec_store: Arc<Mutex<HashMap<String, ExecBuffer>>>,
        poll_kernels: Arc<Mutex<HashMap<String, KernelState>>>,
        stdin: Arc<Mutex<ChildStdin>>,
        shutdown: CancellationToken,
    ) {
        let mut reader = BufReader::new(stdout).lines();

        loop {
            let line = tokio::select! {
                _ = shutdown.cancelled() => break,
                res = reader.next_line() => match res {
                    Ok(Some(line)) => line,
                    Ok(None) => break,
                    Err(err) => {
                        warn!("js_repl kernel stream ended: {err}");
                        break;
                    }
                },
            };

            let parsed: Result<KernelToHost, _> = serde_json::from_str(&line);
            let msg = match parsed {
                Ok(m) => m,
                Err(err) => {
                    warn!("js_repl kernel sent invalid json: {err} (line: {line})");
                    continue;
                }
            };

            match msg {
                KernelToHost::ExecLog { id, text } => {
                    let mut store = exec_store.lock().await;
                    if let Some(entry) = store.get_mut(&id) {
                        entry.logs.push_back(text.clone());
                        entry.all_logs.push(text);
                        entry.notify.notify_waiters();
                    }
                }
                KernelToHost::ExecResult {
                    id,
                    ok,
                    output,
                    error,
                } => {
                    JsReplManager::wait_for_exec_tool_calls_map(&exec_tool_calls, &id).await;
                    let mut pending = pending_execs.lock().await;
                    if let Some(tx) = pending.remove(&id) {
                        let payload = if ok {
                            ExecResultMessage::Ok {
                                output: output.clone(),
                            }
                        } else {
                            ExecResultMessage::Err {
                                message: error
                                    .clone()
                                    .unwrap_or_else(|| "js_repl execution failed".to_string()),
                            }
                        };
                        let _ = tx.send(payload);
                    }
                    let mut store = exec_store.lock().await;
                    if let Some(entry) = store.get_mut(&id) {
                        entry.done = true;
                        entry.output = Some(output);
                        entry.error = error;
                        entry.notify.notify_waiters();
                    }
                    exec_contexts.lock().await.remove(&id);
                    JsReplManager::clear_exec_tool_calls_map(&exec_tool_calls, &id).await;
                    let state = poll_kernels.lock().await.remove(&id);
                    if let Some(state) = state {
                        state.shutdown.cancel();
                    }
                }
                KernelToHost::RunTool(req) => {
                    if !JsReplManager::begin_exec_tool_call(&exec_tool_calls, &req.exec_id).await {
                        let payload = HostToKernel::RunToolResult(RunToolResult {
                            id: req.id,
                            ok: false,
                            response: None,
                            error: Some("js_repl exec context not found".to_string()),
                        });
                        if let Err(err) = JsReplManager::write_message(&stdin, &payload).await {
                            warn!("failed to reply to kernel run_tool request: {err}");
                        }
                        continue;
                    }
                    let stdin_clone = Arc::clone(&stdin);
                    let exec_contexts = Arc::clone(&exec_contexts);
                    let exec_tool_calls = Arc::clone(&exec_tool_calls);
                    tokio::spawn(async move {
                        let exec_id = req.exec_id.clone();
                        let context = { exec_contexts.lock().await.get(&exec_id).cloned() };
                        let result = match context {
                            Some(ctx) => JsReplManager::run_tool_request(ctx, req).await,
                            None => RunToolResult {
                                id: req.id.clone(),
                                ok: false,
                                response: None,
                                error: Some("js_repl exec context not found".to_string()),
                            },
                        };
                        JsReplManager::finish_exec_tool_call(&exec_tool_calls, &exec_id).await;
                        let payload = HostToKernel::RunToolResult(result);
                        if let Err(err) = JsReplManager::write_message(&stdin_clone, &payload).await
                        {
                            warn!("failed to reply to kernel run_tool request: {err}");
                        }
                    });
                }
            }
        }

        let exec_ids = {
            let mut contexts = exec_contexts.lock().await;
            let ids = contexts.keys().cloned().collect::<Vec<_>>();
            contexts.clear();
            ids
        };
        for exec_id in exec_ids {
            JsReplManager::wait_for_exec_tool_calls_map(&exec_tool_calls, &exec_id).await;
            JsReplManager::clear_exec_tool_calls_map(&exec_tool_calls, &exec_id).await;
        }
        let mut pending = pending_execs.lock().await;
        for (_id, tx) in pending.drain() {
            let _ = tx.send(ExecResultMessage::Err {
                message: "js_repl kernel exited unexpectedly".to_string(),
            });
        }
        drop(pending);
        let exec_ids_from_contexts = {
            let mut contexts = exec_contexts.lock().await;
            let ids: Vec<String> = contexts.keys().cloned().collect();
            contexts.clear();
            ids
        };
        let mut affected_exec_ids: HashSet<String> = exec_ids_from_contexts.into_iter().collect();
        {
            let kernels = poll_kernels.lock().await;
            affected_exec_ids.extend(
                kernels
                    .iter()
                    .filter(|(_, state)| Arc::ptr_eq(&state.stdin, &stdin))
                    .map(|(exec_id, _)| exec_id.clone()),
            );
        }
        let mut store = exec_store.lock().await;
        for exec_id in &affected_exec_ids {
            if let Some(entry) = store.get_mut(exec_id)
                && !entry.done
            {
                entry.done = true;
                entry.error = Some("js_repl kernel exited unexpectedly".to_string());
                entry.notify.notify_waiters();
            }
        }
        drop(store);
        let mut kernels = poll_kernels.lock().await;
        for exec_id in affected_exec_ids {
            kernels.remove(&exec_id);
        }
    }

    async fn run_tool_request(exec: ExecContext, req: RunToolRequest) -> RunToolResult {
        if is_js_repl_internal_tool(&req.tool_name) {
            return RunToolResult {
                id: req.id,
                ok: false,
                response: None,
                error: Some("js_repl cannot invoke itself".to_string()),
            };
        }

        let mcp_tools = exec
            .session
            .services
            .mcp_connection_manager
            .read()
            .await
            .list_all_tools()
            .await;

        let router = ToolRouter::from_config(
            &exec.turn.tools_config,
            Some(
                mcp_tools
                    .into_iter()
                    .map(|(name, tool)| (name, tool.tool))
                    .collect(),
            ),
            exec.turn.dynamic_tools.as_slice(),
        );

        let payload =
            if let Some((server, tool)) = exec.session.parse_mcp_tool_name(&req.tool_name).await {
                crate::tools::context::ToolPayload::Mcp {
                    server,
                    tool,
                    raw_arguments: req.arguments.clone(),
                }
            } else if is_freeform_tool(&router.specs(), &req.tool_name) {
                crate::tools::context::ToolPayload::Custom {
                    input: req.arguments.clone(),
                }
            } else {
                crate::tools::context::ToolPayload::Function {
                    arguments: req.arguments.clone(),
                }
            };

        let call = crate::tools::router::ToolCall {
            tool_name: req.tool_name,
            call_id: req.id.clone(),
            payload,
        };

        match router
            .dispatch_tool_call(
                exec.session,
                exec.turn,
                exec.tracker,
                call,
                crate::tools::router::ToolCallSource::JsRepl,
            )
            .await
        {
            Ok(response) => match serde_json::to_value(response) {
                Ok(value) => RunToolResult {
                    id: req.id,
                    ok: true,
                    response: Some(value),
                    error: None,
                },
                Err(err) => RunToolResult {
                    id: req.id,
                    ok: false,
                    response: None,
                    error: Some(format!("failed to serialize tool output: {err}")),
                },
            },
            Err(err) => RunToolResult {
                id: req.id,
                ok: false,
                response: None,
                error: Some(err.to_string()),
            },
        }
    }

    fn configure_js_repl_env(&self, env: &mut HashMap<String, String>) {
        scrub_js_repl_env(env);

        env.insert(
            "CODEX_JS_TMP_DIR".to_string(),
            self.tmp_dir.path().to_string_lossy().to_string(),
        );
        env.insert(
            "CODEX_JS_REPL_HOME".to_string(),
            self.js_repl_home.to_string_lossy().to_string(),
        );
        env.insert(
            "CODEX_JS_REPL_VENDOR_NODE_MODULES".to_string(),
            self.vendor_node_modules.to_string_lossy().to_string(),
        );
        env.insert(
            "CODEX_JS_REPL_USER_NODE_MODULES".to_string(),
            self.user_node_modules.to_string_lossy().to_string(),
        );

        if let Ok(node_path) = std::env::join_paths([
            self.vendor_node_modules.as_path(),
            self.user_node_modules.as_path(),
        ]) {
            env.insert(
                "NODE_PATH".to_string(),
                node_path.to_string_lossy().to_string(),
            );
        }
        env.insert(
            "NODE_REPL_HISTORY".to_string(),
            self.js_repl_home
                .join("node_repl_history")
                .to_string_lossy()
                .to_string(),
        );

        env.insert(
            "HOME".to_string(),
            self.js_repl_home.to_string_lossy().to_string(),
        );
        if cfg!(windows) {
            env.insert(
                "USERPROFILE".to_string(),
                self.js_repl_home.to_string_lossy().to_string(),
            );
            env.insert(
                "APPDATA".to_string(),
                self.js_repl_home
                    .join("appdata")
                    .to_string_lossy()
                    .to_string(),
            );
            env.insert(
                "LOCALAPPDATA".to_string(),
                self.js_repl_home
                    .join("localappdata")
                    .to_string_lossy()
                    .to_string(),
            );
        }

        env.insert(
            "XDG_CONFIG_HOME".to_string(),
            self.xdg_config_dir.to_string_lossy().to_string(),
        );
        env.insert(
            "XDG_CACHE_HOME".to_string(),
            self.xdg_cache_dir.to_string_lossy().to_string(),
        );
        env.insert(
            "XDG_DATA_HOME".to_string(),
            self.xdg_data_dir.to_string_lossy().to_string(),
        );

        let npm_config_path = self.npm_config_path.to_string_lossy().to_string();
        set_env_with_upper(env, "npm_config_userconfig", &npm_config_path);
        set_env_with_upper(env, "npm_config_globalconfig", &npm_config_path);
        set_env_with_upper(
            env,
            "npm_config_cache",
            self.npm_cache_dir.to_string_lossy().as_ref(),
        );
        set_env_with_upper(
            env,
            "npm_config_tmp",
            self.npm_tmp_dir.to_string_lossy().as_ref(),
        );
        set_env_with_upper(
            env,
            "npm_config_prefix",
            self.npm_prefix_dir.to_string_lossy().as_ref(),
        );
        set_env_with_upper(env, "npm_config_update_notifier", "false");
        set_env_with_upper(env, "npm_config_fund", "false");
        set_env_with_upper(env, "npm_config_audit", "false");

        env.insert(
            "YARN_CACHE_FOLDER".to_string(),
            self.yarn_cache_dir.to_string_lossy().to_string(),
        );
        env.insert(
            "YARN_RC_FILENAME".to_string(),
            self.js_repl_home
                .join(".codex-yarnrc")
                .to_string_lossy()
                .to_string(),
        );

        env.insert(
            "PNPM_STORE_PATH".to_string(),
            self.pnpm_store_dir.to_string_lossy().to_string(),
        );
        env.insert(
            "COREPACK_HOME".to_string(),
            self.corepack_home.to_string_lossy().to_string(),
        );
    }

    async fn read_stderr(stderr: tokio::process::ChildStderr, shutdown: CancellationToken) {
        let mut reader = BufReader::new(stderr).lines();

        loop {
            let line = tokio::select! {
                _ = shutdown.cancelled() => break,
                res = reader.next_line() => match res {
                    Ok(Some(line)) => line,
                    Ok(None) => break,
                    Err(err) => {
                        warn!("js_repl kernel stderr ended: {err}");
                        break;
                    }
                },
            };
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                warn!("js_repl stderr: {trimmed}");
            }
        }
    }
}

fn is_freeform_tool(specs: &[ToolSpec], name: &str) -> bool {
    specs
        .iter()
        .any(|spec| spec.name() == name && matches!(spec, ToolSpec::Freeform(_)))
}

fn is_js_repl_internal_tool(name: &str) -> bool {
    matches!(name, "js_repl" | "js_repl_poll" | "js_repl_reset")
}

fn scrub_js_repl_env(env: &mut HashMap<String, String>) {
    let prefixes = ["NODE_", "NPM_CONFIG_", "YARN_", "PNPM_", "COREPACK_"];
    let keys: Vec<String> = env.keys().cloned().collect();
    for key in keys {
        let upper = key.to_ascii_uppercase();
        if prefixes.iter().any(|prefix| upper.starts_with(prefix)) {
            env.remove(&key);
        }
    }
}

fn set_env_with_upper(env: &mut HashMap<String, String>, key: &str, value: &str) {
    env.insert(key.to_string(), value.to_string());
    let upper = key.to_ascii_uppercase();
    if upper != key {
        env.insert(upper, value.to_string());
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum KernelToHost {
    ExecLog {
        id: String,
        text: String,
    },
    ExecResult {
        id: String,
        ok: bool,
        output: String,
        #[serde(default)]
        error: Option<String>,
    },
    RunTool(RunToolRequest),
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HostToKernel {
    Exec {
        id: String,
        code: String,
        #[serde(default)]
        timeout_ms: Option<u64>,
        #[serde(default)]
        stream_logs: bool,
    },
    RunToolResult(RunToolResult),
}

#[derive(Clone, Debug, Deserialize)]
struct RunToolRequest {
    id: String,
    exec_id: String,
    tool_name: String,
    arguments: String,
}

#[derive(Clone, Debug, Serialize)]
struct RunToolResult {
    id: String,
    ok: bool,
    #[serde(default)]
    response: Option<JsonValue>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug)]
enum ExecResultMessage {
    Ok { output: String },
    Err { message: String },
}

fn clamp_poll_ms(value: Option<u64>) -> u64 {
    value
        .unwrap_or(JS_REPL_POLL_DEFAULT_MS)
        .clamp(JS_REPL_POLL_MIN_MS, JS_REPL_POLL_MAX_MS)
}

async fn prepare_js_repl_home(
    js_repl_home: &Path,
) -> Result<
    (
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
    ),
    std::io::Error,
> {
    let vendor_root = js_repl_home.join("codex_node_modules");
    let vendor_node_modules = vendor_root.join("node_modules");
    let user_node_modules = js_repl_home.join("node_modules");
    let npm_config_path = js_repl_home.join("npmrc");
    let npm_cache_dir = js_repl_home.join("npm-cache");
    let npm_tmp_dir = js_repl_home.join("npm-tmp");
    let npm_prefix_dir = js_repl_home.join("npm-prefix");
    let xdg_config_dir = js_repl_home.join("xdg-config");
    let xdg_cache_dir = js_repl_home.join("xdg-cache");
    let xdg_data_dir = js_repl_home.join("xdg-data");
    let yarn_cache_dir = js_repl_home.join("yarn-cache");
    let pnpm_store_dir = js_repl_home.join("pnpm-store");
    let corepack_home = js_repl_home.join("corepack");

    for dir in [
        js_repl_home,
        &vendor_root,
        &vendor_node_modules,
        &user_node_modules,
        &npm_cache_dir,
        &npm_tmp_dir,
        &npm_prefix_dir,
        &xdg_config_dir,
        &xdg_cache_dir,
        &xdg_data_dir,
        &yarn_cache_dir,
        &pnpm_store_dir,
        &corepack_home,
    ] {
        tokio::fs::create_dir_all(dir).await?;
    }

    if tokio::fs::metadata(&npm_config_path).await.is_err() {
        tokio::fs::write(&npm_config_path, b"").await?;
    }

    Ok((
        vendor_node_modules,
        user_node_modules,
        npm_config_path,
        npm_cache_dir,
        npm_tmp_dir,
        npm_prefix_dir,
        xdg_config_dir,
        xdg_cache_dir,
        xdg_data_dir,
        yarn_cache_dir,
        pnpm_store_dir,
        corepack_home,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct NodeVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

impl fmt::Display for NodeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl NodeVersion {
    fn parse(input: &str) -> Result<Self, String> {
        let trimmed = input.trim().trim_start_matches('v');
        let mut parts = trimmed.split(['.', '-', '+']);
        let major = parts
            .next()
            .ok_or_else(|| "missing major version".to_string())?
            .parse::<u64>()
            .map_err(|err| format!("invalid major version: {err}"))?;
        let minor = parts
            .next()
            .ok_or_else(|| "missing minor version".to_string())?
            .parse::<u64>()
            .map_err(|err| format!("invalid minor version: {err}"))?;
        let patch = parts
            .next()
            .ok_or_else(|| "missing patch version".to_string())?
            .parse::<u64>()
            .map_err(|err| format!("invalid patch version: {err}"))?;
        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

fn required_node_version() -> Result<NodeVersion, String> {
    NodeVersion::parse(JS_REPL_MIN_NODE_VERSION)
}

async fn read_node_version(node_path: &Path) -> Result<NodeVersion, String> {
    let output = tokio::process::Command::new(node_path)
        .arg("--version")
        .output()
        .await
        .map_err(|err| format!("failed to execute Node: {err}"))?;

    if !output.status.success() {
        let mut details = String::new();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = stdout.trim();
        let stderr = stderr.trim();
        if !stdout.is_empty() {
            details.push_str(" stdout: ");
            details.push_str(stdout);
        }
        if !stderr.is_empty() {
            details.push_str(" stderr: ");
            details.push_str(stderr);
        }
        let details = if details.is_empty() {
            String::new()
        } else {
            format!(" ({details})")
        };
        return Err(format!(
            "failed to read Node version (status {status}){details}",
            status = output.status
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();
    NodeVersion::parse(stdout)
        .map_err(|err| format!("failed to parse Node version output `{stdout}`: {err}"))
}

async fn ensure_node_version(node_path: &Path) -> Result<(), String> {
    let required = required_node_version()?;
    let found = read_node_version(node_path).await?;
    if found < required {
        return Err(format!(
            "Node runtime too old for js_repl (resolved {node_path}): found v{found}, requires >= v{required}. Install/update Node or set js_repl_node_path to a newer runtime.",
            node_path = node_path.display()
        ));
    }
    Ok(())
}

pub(crate) fn resolve_node(config_path: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("CODEX_JS_REPL_NODE_PATH") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }

    if let Some(path) = config_path
        && path.exists()
    {
        return Some(path.to_path_buf());
    }

    if let Ok(exec_path) = std::env::current_exe()
        && let Some(candidate) = resolve_bundled_node(&exec_path)
    {
        return Some(candidate);
    }

    if let Ok(path) = which::which("node") {
        return Some(path);
    }

    None
}

fn resolve_bundled_node(exec_path: &Path) -> Option<PathBuf> {
    let target = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") => "aarch64-unknown-linux-musl",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        ("windows", "aarch64") => "aarch64-pc-windows-msvc",
        _ => return None,
    };

    let mut path = exec_path.to_path_buf();
    if let Some(parent) = path.parent() {
        path = parent.to_path_buf();
    }
    let mut dir = path;
    for _ in 0..4 {
        if dir.join("vendor").exists() {
            break;
        }
        dir = match dir.parent() {
            Some(parent) => parent.to_path_buf(),
            None => break,
        };
    }
    let candidate = dir
        .join("vendor")
        .join(target)
        .join("node")
        .join(if cfg!(windows) { "node.exe" } else { "node" });
    if candidate.exists() {
        return Some(candidate);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codex::make_session_and_context;
    use crate::protocol::AskForApproval;
    use crate::protocol::SandboxPolicy;
    use crate::turn_diff_tracker::TurnDiffTracker;
    use codex_protocol::models::ContentItem;
    use codex_protocol::models::ResponseInputItem;
    use codex_protocol::openai_models::InputModality;
    use pretty_assertions::assert_eq;

    #[test]
    fn node_version_parses_v_prefix_and_suffix() {
        let version = NodeVersion::parse("v25.1.0-nightly.2024").unwrap();
        assert_eq!(
            version,
            NodeVersion {
                major: 25,
                minor: 1,
                patch: 0,
            }
        );
    }

    #[test]
    fn js_repl_internal_tool_guard_matches_expected_names() {
        assert!(is_js_repl_internal_tool("js_repl"));
        assert!(is_js_repl_internal_tool("js_repl_poll"));
        assert!(is_js_repl_internal_tool("js_repl_reset"));
        assert!(!is_js_repl_internal_tool("shell_command"));
        assert!(!is_js_repl_internal_tool("list_mcp_resources"));
    }

    async fn can_run_js_repl_runtime_tests() -> bool {
        if std::env::var_os("CODEX_SANDBOX").is_some() {
            return false;
        }
        let Some(node_path) = resolve_node(None) else {
            return false;
        };
        let required = match required_node_version() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let found = match read_node_version(&node_path).await {
            Ok(v) => v,
            Err(_) => return false,
        };
        found >= required
    }

    #[tokio::test]
    async fn js_repl_persists_top_level_bindings_and_supports_tla() -> anyhow::Result<()> {
        if !can_run_js_repl_runtime_tests().await {
            return Ok(());
        }

        let (session, turn) = make_session_and_context().await;
        let session = Arc::new(session);
        let turn = Arc::new(turn);
        let tracker = Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::default()));
        let manager = turn.js_repl.manager().await?;

        let first = manager
            .execute(
                Arc::clone(&session),
                Arc::clone(&turn),
                Arc::clone(&tracker),
                JsReplArgs {
                    code: "let x = await Promise.resolve(41); console.log(x);".to_string(),
                    timeout_ms: Some(10_000),
                    poll: false,
                },
            )
            .await?;
        assert!(first.output.contains("41"));

        let second = manager
            .execute(
                Arc::clone(&session),
                Arc::clone(&turn),
                Arc::clone(&tracker),
                JsReplArgs {
                    code: "console.log(x + 1);".to_string(),
                    timeout_ms: Some(10_000),
                    poll: false,
                },
            )
            .await?;

        assert!(second.output.contains("42"));
        Ok(())
    }

    #[tokio::test]
    async fn js_repl_timeout_does_not_deadlock() -> anyhow::Result<()> {
        if !can_run_js_repl_runtime_tests().await {
            return Ok(());
        }

        let (session, turn) = make_session_and_context().await;
        let session = Arc::new(session);
        let turn = Arc::new(turn);
        let tracker = Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::default()));
        let manager = turn.js_repl.manager().await?;

        let result = tokio::time::timeout(
            Duration::from_secs(3),
            manager.execute(
                session,
                turn,
                tracker,
                JsReplArgs {
                    code: "while (true) {}".to_string(),
                    timeout_ms: Some(50),
                    poll: false,
                },
            ),
        )
        .await
        .expect("execute should return, not deadlock")
        .expect_err("expected timeout error");

        assert_eq!(
            result.to_string(),
            "js_repl execution timed out; kernel reset, rerun your request"
        );
        Ok(())
    }

    #[tokio::test]
    async fn js_repl_can_call_tools() -> anyhow::Result<()> {
        if !can_run_js_repl_runtime_tests().await {
            return Ok(());
        }

        let (session, mut turn) = make_session_and_context().await;
        turn.approval_policy = AskForApproval::Never;
        turn.sandbox_policy = SandboxPolicy::DangerFullAccess;

        let session = Arc::new(session);
        let turn = Arc::new(turn);
        let tracker = Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::default()));
        let manager = turn.js_repl.manager().await?;

        let shell = manager
            .execute(
                Arc::clone(&session),
                Arc::clone(&turn),
                Arc::clone(&tracker),
                JsReplArgs {
                    code: "const shellOut = await codex.tool(\"shell_command\", { command: \"printf js_repl_shell_ok\" }); console.log(JSON.stringify(shellOut));".to_string(),
                    timeout_ms: Some(15_000),
                    poll: false,
                },
            )
            .await?;
        assert!(shell.output.contains("js_repl_shell_ok"));

        let tool = manager
            .execute(
                Arc::clone(&session),
                Arc::clone(&turn),
                Arc::clone(&tracker),
                JsReplArgs {
                    code: "const toolOut = await codex.tool(\"list_mcp_resources\", {}); console.log(toolOut.type);".to_string(),
                    timeout_ms: Some(15_000),
                    poll: false,
                },
            )
            .await?;
        assert!(tool.output.contains("function_call_output"));
        Ok(())
    }

    #[tokio::test]
    async fn js_repl_tool_call_rejects_recursive_js_repl_invocation() -> anyhow::Result<()> {
        if !can_run_js_repl_runtime_tests().await {
            return Ok(());
        }

        let (session, mut turn) = make_session_and_context().await;
        turn.approval_policy = AskForApproval::Never;
        turn.sandbox_policy = SandboxPolicy::DangerFullAccess;

        let session = Arc::new(session);
        let turn = Arc::new(turn);
        let tracker = Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::default()));
        let manager = turn.js_repl.manager().await?;

        let result = manager
            .execute(
                session,
                turn,
                tracker,
                JsReplArgs {
                    code: r#"
try {
  await codex.tool("js_repl", "console.log('recursive')");
  console.log("unexpected-success");
} catch (err) {
  console.log(String(err));
}
"#
                    .to_string(),
                    timeout_ms: Some(15_000),
                    poll: false,
                },
            )
            .await?;

        assert!(
            result.output.contains("js_repl cannot invoke itself"),
            "expected recursion guard message, got output: {}",
            result.output
        );
        assert!(
            !result.output.contains("unexpected-success"),
            "recursive js_repl tool call unexpectedly succeeded: {}",
            result.output
        );
        Ok(())
    }

    #[tokio::test]
    async fn js_repl_waits_for_unawaited_tool_calls_before_completion() -> anyhow::Result<()> {
        if !can_run_js_repl_runtime_tests().await || cfg!(windows) {
            return Ok(());
        }

        let (session, mut turn) = make_session_and_context().await;
        turn.approval_policy = AskForApproval::Never;
        turn.sandbox_policy = SandboxPolicy::DangerFullAccess;

        let session = Arc::new(session);
        let turn = Arc::new(turn);
        let tracker = Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::default()));
        let manager = turn.js_repl.manager().await?;

        let marker = turn
            .cwd
            .join(format!("js-repl-unawaited-marker-{}.txt", Uuid::new_v4()));
        let marker_json = serde_json::to_string(&marker.to_string_lossy().to_string())?;
        let result = manager
            .execute(
                session,
                turn,
                tracker,
                JsReplArgs {
                    code: format!(
                        r#"
const marker = {marker_json};
void codex.tool("shell_command", {{ command: `sleep 0.35; printf js_repl_unawaited_done > "${{marker}}"` }});
console.log("cell-complete");
"#
                    ),
                    timeout_ms: Some(10_000),
                    poll: false,
                },
            )
            .await?;
        assert!(result.output.contains("cell-complete"));
        let marker_contents = tokio::fs::read_to_string(&marker).await?;
        assert_eq!(marker_contents, "js_repl_unawaited_done");
        let _ = tokio::fs::remove_file(&marker).await;
        Ok(())
    }

    #[tokio::test]
    async fn js_repl_can_attach_image_via_view_image_tool() -> anyhow::Result<()> {
        if !can_run_js_repl_runtime_tests().await {
            return Ok(());
        }

        let (session, mut turn) = make_session_and_context().await;
        if !turn
            .model_info
            .input_modalities
            .contains(&InputModality::Image)
        {
            return Ok(());
        }
        turn.approval_policy = AskForApproval::Never;
        turn.sandbox_policy = SandboxPolicy::DangerFullAccess;

        let session = Arc::new(session);
        let turn = Arc::new(turn);
        *session.active_turn.lock().await = Some(crate::state::ActiveTurn::default());

        let tracker = Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::default()));
        let manager = turn.js_repl.manager().await?;
        let code = r#"
const fs = await import("node:fs/promises");
const path = await import("node:path");
const imagePath = path.join(codex.tmpDir, "js-repl-view-image.png");
const png = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==",
  "base64"
);
await fs.writeFile(imagePath, png);
const out = await codex.tool("view_image", { path: imagePath });
console.log(out.type);
console.log(out.output?.body?.text ?? "");
"#;

        let result = manager
            .execute(
                Arc::clone(&session),
                turn,
                tracker,
                JsReplArgs {
                    code: code.to_string(),
                    timeout_ms: Some(15_000),
                    poll: false,
                },
            )
            .await?;
        assert!(result.output.contains("function_call_output"));
        assert!(result.output.contains("attached local image path"));

        let pending_input = session.get_pending_input().await;
        let image_url = pending_input
            .iter()
            .find_map(|item| match item {
                ResponseInputItem::Message { content, .. } => {
                    content.iter().find_map(|content_item| match content_item {
                        ContentItem::InputImage { image_url } => Some(image_url.as_str()),
                        _ => None,
                    })
                }
                _ => None,
            })
            .expect("view_image should inject an input_image message for the active turn");
        assert!(image_url.starts_with("data:image/png;base64,"));

        Ok(())
    }

    #[tokio::test]
    async fn js_repl_does_not_expose_process_global() -> anyhow::Result<()> {
        if !can_run_js_repl_runtime_tests().await {
            return Ok(());
        }

        let (session, turn) = make_session_and_context().await;
        let session = Arc::new(session);
        let turn = Arc::new(turn);
        let tracker = Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::default()));
        let manager = turn.js_repl.manager().await?;

        let result = manager
            .execute(
                session,
                turn,
                tracker,
                JsReplArgs {
                    code: "console.log(typeof process);".to_string(),
                    timeout_ms: Some(10_000),
                    poll: false,
                },
            )
            .await?;
        assert!(result.output.contains("undefined"));
        Ok(())
    }

    #[tokio::test]
    async fn js_repl_blocks_sensitive_builtin_imports() -> anyhow::Result<()> {
        if !can_run_js_repl_runtime_tests().await {
            return Ok(());
        }

        let (session, turn) = make_session_and_context().await;
        let session = Arc::new(session);
        let turn = Arc::new(turn);
        let tracker = Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::default()));
        let manager = turn.js_repl.manager().await?;

        let err = manager
            .execute(
                session,
                turn,
                tracker,
                JsReplArgs {
                    code: "await import(\"node:process\");".to_string(),
                    timeout_ms: Some(10_000),
                    poll: false,
                },
            )
            .await
            .expect_err("node:process import should be blocked");
        assert!(
            err.to_string()
                .contains("Importing module \"node:process\" is not allowed in js_repl")
        );
        Ok(())
    }

    #[tokio::test]
    async fn js_repl_poll_submit_and_complete() -> anyhow::Result<()> {
        if resolve_node(None).is_none() || std::env::var_os("CODEX_SANDBOX").is_some() {
            return Ok(());
        }

        let (session, mut turn) = make_session_and_context().await;
        turn.approval_policy = AskForApproval::Never;
        turn.sandbox_policy = SandboxPolicy::DangerFullAccess;

        let session = Arc::new(session);
        let turn = Arc::new(turn);
        let tracker = Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::default()));
        let manager = turn.js_repl.manager().await?;

        let submission = Arc::clone(&manager)
            .submit(
                Arc::clone(&session),
                Arc::clone(&turn),
                tracker,
                "call-1".to_string(),
                JsReplArgs {
                    code: "console.log('poll-ok');".to_string(),
                    timeout_ms: Some(5_000),
                    poll: true,
                },
            )
            .await?;

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let result = manager.poll(&submission.exec_id, Some(200)).await?;
            if result.done {
                let output = result.output.unwrap_or_default();
                assert!(output.contains("poll-ok"));
                break;
            }
            if Instant::now() >= deadline {
                panic!("timed out waiting for js_repl poll completion");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        Ok(())
    }

    #[tokio::test]
    async fn js_repl_poll_submit_supports_parallel_execs() -> anyhow::Result<()> {
        if resolve_node(None).is_none() || std::env::var_os("CODEX_SANDBOX").is_some() {
            return Ok(());
        }

        let (session, mut turn) = make_session_and_context().await;
        turn.approval_policy = AskForApproval::Never;
        turn.sandbox_policy = SandboxPolicy::DangerFullAccess;

        let session = Arc::new(session);
        let turn = Arc::new(turn);
        let tracker = Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::default()));
        let manager = turn.js_repl.manager().await?;

        let slow_submission = Arc::clone(&manager)
            .submit(
                Arc::clone(&session),
                Arc::clone(&turn),
                Arc::clone(&tracker),
                "call-slow".to_string(),
                JsReplArgs {
                    code: "await new Promise((resolve) => setTimeout(resolve, 2000)); console.log('slow-done');".to_string(),
                    timeout_ms: Some(10_000),
                    poll: true,
                },
            )
            .await?;

        let fast_submission = Arc::clone(&manager)
            .submit(
                Arc::clone(&session),
                Arc::clone(&turn),
                tracker,
                "call-fast".to_string(),
                JsReplArgs {
                    code: "console.log('fast-done');".to_string(),
                    timeout_ms: Some(10_000),
                    poll: true,
                },
            )
            .await?;

        let fast_start = Instant::now();
        let fast_output = loop {
            let result = manager.poll(&fast_submission.exec_id, Some(200)).await?;
            if result.done {
                break result.output.unwrap_or_default();
            }
            if fast_start.elapsed() > Duration::from_millis(1_500) {
                panic!("fast polled exec did not complete quickly; submit appears serialized");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        assert!(fast_output.contains("fast-done"));

        let slow_deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let result = manager.poll(&slow_submission.exec_id, Some(200)).await?;
            if result.done {
                let output = result.output.unwrap_or_default();
                assert!(output.contains("slow-done"));
                break;
            }
            if Instant::now() >= slow_deadline {
                panic!("timed out waiting for slow polled exec completion");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        Ok(())
    }

    #[tokio::test]
    async fn js_repl_poll_timeout_waits_for_inflight_tool_calls() -> anyhow::Result<()> {
        if !can_run_js_repl_runtime_tests().await || cfg!(windows) {
            return Ok(());
        }

        let (session, mut turn) = make_session_and_context().await;
        turn.approval_policy = AskForApproval::Never;
        turn.sandbox_policy = SandboxPolicy::DangerFullAccess;

        let session = Arc::new(session);
        let turn = Arc::new(turn);
        let tracker = Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::default()));
        let manager = turn.js_repl.manager().await?;

        let started_marker = turn.cwd.join(format!(
            "js-repl-poll-timeout-started-{}.txt",
            Uuid::new_v4()
        ));
        let done_marker = turn
            .cwd
            .join(format!("js-repl-poll-timeout-done-{}.txt", Uuid::new_v4()));
        let started_json = serde_json::to_string(&started_marker.to_string_lossy().to_string())?;
        let done_json = serde_json::to_string(&done_marker.to_string_lossy().to_string())?;
        let submission = Arc::clone(&manager)
            .submit(
                Arc::clone(&session),
                Arc::clone(&turn),
                tracker,
                "call-timeout".to_string(),
                JsReplArgs {
                    code: format!(
                        r#"
const started = {started_json};
const done = {done_json};
void codex.tool("shell_command", {{ command: `printf started > "${{started}}"; sleep 0.6; printf done > "${{done}}"` }});
await new Promise((resolve) => setTimeout(resolve, 150));
await new Promise(() => {{}});
"#
                    ),
                    timeout_ms: Some(350),
                    poll: true,
                },
            )
            .await?;

        let started_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if tokio::fs::metadata(&started_marker).await.is_ok() {
                break;
            }
            if Instant::now() >= started_deadline {
                panic!("timed out waiting for in-flight tool call to start");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let result = manager.poll(&submission.exec_id, Some(200)).await?;
            if result.done {
                assert_eq!(
                    result.error.as_deref(),
                    Some("js_repl execution timed out; kernel reset, rerun your request")
                );
                break;
            }
            if Instant::now() >= deadline {
                panic!("timed out waiting for js_repl poll timeout completion");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let done_contents = tokio::fs::read_to_string(&done_marker).await?;
        assert_eq!(done_contents, "done");
        let _ = tokio::fs::remove_file(&started_marker).await;
        let _ = tokio::fs::remove_file(&done_marker).await;

        Ok(())
    }

    #[tokio::test]
    async fn js_repl_poll_rejects_unknown_exec_id() -> anyhow::Result<()> {
        let (_session, turn) = make_session_and_context().await;
        let manager = turn.js_repl.manager().await?;
        let err = manager
            .poll("missing-exec-id", Some(50))
            .await
            .expect_err("expected missing exec id error");
        assert_eq!(err.to_string(), "js_repl exec id not found");
        Ok(())
    }

    #[tokio::test]
    async fn js_repl_isolated_module_resolution() -> anyhow::Result<()> {
        if resolve_node(None).is_none() || std::env::var_os("CODEX_SANDBOX").is_some() {
            return Ok(());
        }

        let (session, mut turn) = make_session_and_context().await;
        turn.approval_policy = AskForApproval::Never;
        turn.sandbox_policy = SandboxPolicy::DangerFullAccess;
        turn.shell_environment_policy
            .r#set
            .insert("NODE_OPTIONS".to_string(), "--trace-warnings".to_string());
        turn.shell_environment_policy.r#set.insert(
            "npm_config_userconfig".to_string(),
            "/tmp/should-not-see".to_string(),
        );

        let session = Arc::new(session);
        let turn = Arc::new(turn);
        let tracker = Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::default()));
        let manager: Arc<JsReplManager> = turn.js_repl.manager().await?;

        let code = r#"
const fs = await import("node:fs/promises");
const path = await import("node:path");
const os = await import("node:os");
const replHome = os.homedir();
const vendorRoot = path.join(replHome, "codex_node_modules", "node_modules");
const userRoot = path.join(replHome, "node_modules");

const dupeVendorDir = path.join(vendorRoot, "dupe");
await fs.mkdir(dupeVendorDir, { recursive: true });
await fs.writeFile(
  path.join(dupeVendorDir, "package.json"),
  JSON.stringify({ name: "dupe", type: "module", main: "index.js" })
);
await fs.writeFile(path.join(dupeVendorDir, "index.js"), 'export const source = "vendor";');

const dupeUserDir = path.join(userRoot, "dupe");
await fs.mkdir(dupeUserDir, { recursive: true });
await fs.writeFile(
  path.join(dupeUserDir, "package.json"),
  JSON.stringify({ name: "dupe", type: "module", main: "index.js" })
);
await fs.writeFile(path.join(dupeUserDir, "index.js"), 'export const source = "user";');

const userOnlyDir = path.join(userRoot, "user_only");
await fs.mkdir(userOnlyDir, { recursive: true });
await fs.writeFile(
  path.join(userOnlyDir, "package.json"),
  JSON.stringify({ name: "user_only", type: "module", main: "index.js" })
);
await fs.writeFile(path.join(userOnlyDir, "index.js"), 'export const source = "user_only";');

const dupe = await import("dupe");
const userOnly = await import("user_only");

console.log(
  JSON.stringify({
    env: {
      replHome,
      vendorRoot,
      userRoot,
    },
    dupe: dupe.source,
    userOnly: userOnly.source,
  })
);
"#;

        let output = manager
            .execute(
                session,
                turn,
                tracker,
                JsReplArgs {
                    code: code.to_string(),
                    timeout_ms: Some(15_000),
                    poll: false,
                },
            )
            .await?
            .output;
        let parsed: serde_json::Value =
            serde_json::from_str(output.trim()).unwrap_or_else(|_| serde_json::json!({}));
        let env = parsed
            .get("env")
            .and_then(serde_json::Value::as_object)
            .cloned()
            .unwrap_or_default();
        let repl_home = env
            .get("replHome")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let vendor_root = env
            .get("vendorRoot")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let user_root = env
            .get("userRoot")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();

        assert_eq!(
            parsed.get("dupe").and_then(serde_json::Value::as_str),
            Some("vendor")
        );
        assert_eq!(
            parsed.get("userOnly").and_then(serde_json::Value::as_str),
            Some("user_only")
        );
        assert!(vendor_root.contains(repl_home));
        assert!(
            Path::new(vendor_root).ends_with(Path::new("codex_node_modules").join("node_modules"))
        );
        assert!(user_root.contains(repl_home));

        Ok(())
    }
}
