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

val read_secret : unit -> string
val input_password: host:string -> username:string -> string

val with_password : options:options -> ?password:string -> (ssh_session -> 'a) -> 'a
val with_shell_channel : session:ssh_session -> (shell_handle -> string -> 'a) -> 'a
val execute : ?read_stderr:bool -> ?read_timeout:int -> shell_handle -> string -> string
val scp : session:ssh_session -> src_path:string -> dst_path:string -> mode:int -> unit
