require "llvm"

LLVM.init_native_target

triple = LLVM.default_target_triple
target = LLVM::Target.from_triple(triple)
machine = target.create_target_machine(triple)

ctx = LLVM::Context.new
mod = ctx.new_module("main")
mod.data_layout = machine.data_layout

main_func = mod.functions.add("main", [] of LLVM::Type, ctx.int32)
bb = main_func.basic_blocks.append("entry")

builder = ctx.new_builder
builder.position_at_end(bb)
builder.ret(ctx.int32.const_int(0))

mod.verify

machine.emit_asm_to_file(mod, "a.s")
