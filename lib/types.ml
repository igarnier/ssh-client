type ssh_session

type ssh_channel

type error_code =
  | SSH_OK
  | SSH_ERROR
  | SSH_AGAIN
  | SSH_EOF
  | SSH_UNKNOWN
