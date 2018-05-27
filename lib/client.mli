open Common

module Channel :
sig
  val read_timeout : ssh_channel -> bool -> int -> string
  val write : ssh_channel -> string -> error_code
end

(** Different log levels in increasing order of verbosity *)
type log_level =
  | SSH_LOG_NOLOG     (** No logging at all *)
  | SSH_LOG_WARNING   (** Only warnings *)
  | SSH_LOG_PROTOCOL  (** High level protocol information *)
  | SSH_LOG_PACKET    (** Lower level protocol infomations, packet level *)
  | SSH_LOG_FUNCTIONS (** Every function path *)

(** Different kinds of authentication accepted by libssh *)
type auth =
  | Auto        (** Authenticate using the Ssh agent, assuming its running *)
  | Interactive (** Type in the password on the command line*)

(** Options needed when connecting over ssh *)
type options = { host: string;
                 username : string;
                 port : int;
                 log_level : log_level;
                 auth : auth
               }

(** Connect and authenticate a ssh connection *)
val connect_and_auth : options -> ssh_session -> unit

(** Execute a remote command, get result as a string *)
val exec : command:string -> ssh_session -> string

(* val with_session : (ssh_session -> 'a) -> options -> 'a *)

(** Creates a channel from the given session and requests a shell on it. Warning: no pty is requested. *)
val with_shell : (ssh_channel -> 'a) -> ssh_session -> 'a

val scp : src_path:string -> base_path:string -> dst_filename:string -> mode:int -> ssh_session -> unit
