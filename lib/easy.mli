open Types
    
(** For now, only Interactive is supported. *)
type auth =
  | Auto
  | Interactive

type options =
  { host      : string;
    username  : string;
    port      : int;
    log_level : ssh_verbosity }

type shell_handle

val with_password : options:options -> (ssh_session -> 'a) -> 'a
val with_shell_channel : session:ssh_session -> (shell_handle -> 'a) -> 'a
val execute : ?read_stderr:bool -> ?read_timeout:int -> shell_handle -> string -> string
