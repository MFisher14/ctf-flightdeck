;; The build-time self-test of ctf-runtime-wasm (B-242): our own module, never a delivered one.
;; `decode` rewrites the bytes at 64 in place (each minus one), so finding the token in the trace
;; proves the runner ran it.
(module
  (memory (export "memory") 1)
  (data (i32.const 64) "dug.tfmguftu.pl")
  (func (export "decode") (result i32)
    (local $i i32)
    (loop $next
      (i32.store8 (i32.add (i32.const 64) (local.get $i))
        (i32.sub (i32.load8_u (i32.add (i32.const 64) (local.get $i))) (i32.const 1)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $next (i32.lt_u (local.get $i) (i32.const 15))))
    (i32.const 64)))
