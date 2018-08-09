This library provides bindings for the client part of [libssh](https://www.libssh.org).
It started its life as a fork of [ocaml-libssh](https://opam.ocaml.org/packages/libssh)
but then took a life of its own.

The library consists of low-level bindings, which can be accessed through the module `Raw`,
on top which high-level functionalities are built (module `Easy`).

* INSTALL

1) Install the `batteries` package via `opam` and libssh (including the dev package)
using your OS's package manager.
2) `jbuilder build && jbuilder install`