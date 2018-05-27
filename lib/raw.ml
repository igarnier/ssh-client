open Types

external version : unit -> string = "libssh_ml_version"

module Session =
struct

  external init : unit -> ssh_session = "libssh_ml_ssh_init"

  external connect : ssh_session -> error_code = "libssh_ml_ssh_connect"

  external disconnect : ssh_session -> error_code = "libssh_ml_ssh_disconnect"

  external close : ssh_session -> unit = "libssh_ml_ssh_close"

end

module Channel =
struct

  (** Can raise exception "Failure" *)
  external create : ssh_session -> ssh_channel = "libssh_ml_channel_create"

  (** Does not raise *)
  external close : ssh_channel -> error_code = "libssh_ml_channel_close"

  (** Does not raise *)  
  external free : ssh_channel -> unit = "libssh_ml_channel_free"

  (** Does not raise *)    
  external open_session : ssh_channel -> error_code = "libssh_ml_channel_open_session"

  (** Can raise exception "Failure" *)
  external request_exec : ssh_channel -> string -> error_code = "libssh_ml_channel_request_exec"

  (** Does not raise *)
  external request_pty : ssh_channel -> error_code = "libssh_ml_channel_request_pty"

  (** Does not raise *)  
  external change_pty_size : ssh_channel -> int -> int -> error_code = "libssh_ml_channel_change_pty_size"

  (** Does not raise *)  
  external request_shell : ssh_channel -> error_code = "libssh_ml_channel_request_shell"      

  (** Can raise exception "Failure" *)
  external read_timeout : ssh_channel -> bool -> int -> string = "libssh_ml_channel_read_timeout"

  (** Can raise exception "Failure" *)
  external write : ssh_channel -> string -> error_code = "libssh_ml_channel_write"

  (** Does not raise *)  
  external send_eof : ssh_channel -> error_code = "libssh_ml_channel_send_eof"

end

