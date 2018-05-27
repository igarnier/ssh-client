(** Abstract type for an ssh session*)
type ssh_session

(** Abstract type for an ssh channel *)
type ssh_channel

(** Low-level libssh error codes *)
type error_code =
  | SSH_OK
  | SSH_ERROR
  | SSH_AGAIN
  | SSH_EOF
  | SSH_UNKNOWN

(** libssh's version *)
external version : unit -> string = "libssh_ml_version"

(** Create a fresh ssh_session *)
(* external init : unit -> ssh_session = "libssh_ml_ssh_init"
 * 
 * (\** Connects to the server (after options have been set) *\)
 * external connect : ssh_session -> error_code = "libssh_ml_ssh_connect"
 * 
 * external disconnect : ssh_session -> error_code = "libssh_ml_ssh_disconnect"
 * 
 * (\** Close a ssh_session *\)
 * external close : ssh_session -> unit = "libssh_ml_ssh_close" *)


(** Forks a sub-process and initializes a fresh session inside. Allows to
    circumvent libssh's statefulness.  *)
val with_session : (ssh_session -> 'a) -> 'a
