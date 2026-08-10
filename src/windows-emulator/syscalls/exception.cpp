#include "../std_include.hpp"
#include "../emulator_utils.hpp"
#include "../syscall_utils.hpp"
#include "../exception_dispatch.hpp"

namespace sogen
{

    namespace syscalls
    {
        NTSTATUS handle_NtRaiseHardError(const syscall_context& c, const NTSTATUS error_status, const ULONG number_of_parameters,
                                         const emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>> /*unicode_string_parameter_mask*/,
                                         const uint64_t parameters, const HARDERROR_RESPONSE_OPTION /*valid_response_option*/,
                                         const emulator_object<HARDERROR_RESPONSE> response)
        {
            if (response)
            {
                response.try_write(ResponseAbort);
            }

            if (error_status & STATUS_SERVICE_NOTIFICATION && number_of_parameters >= 3)
            {
                std::array<uint64_t, 3> params = {0, 0, 0};

                try
                {
                    if (c.emu.try_read_memory(parameters, &params, sizeof(params)))
                    {
                        const auto message =
                            read_unicode_string(c.emu, emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>>{c.emu, params[0]});
                        c.win_emu.log.error("Error Message: %s\n", u16_to_u8(message).c_str());
                    }
                }
                catch (...)
                {
                    // ignore
                }
            }

            c.proc.exit_status = error_status;
            c.win_emu.callbacks.on_exception();
            c.emu.stop();

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtRaiseException(const syscall_context& c,
                                         const emulator_object<EMU_EXCEPTION_RECORD<EmulatorTraits<Emu64>>> exception_record,
                                         const emulator_object<CONTEXT64> thread_context, const BOOLEAN handle_exception)
        {
            auto record = exception_record.read();
            auto ctx = thread_context.read();

            if (handle_exception)
            {
                // First-chance software exception (RtlRaiseException / C++ throw / VMProtect SEH-based
                // control flow). Dispatch it to the guest KiUserExceptionDispatcher with the captured
                // raise-point record + context so SEH/VEH handlers run and execution can continue,
                // instead of aborting the emulation.
                c.write_status = false;
                dispatch_raised_exception(c.win_emu, c.vcpu, record, ctx);
                return STATUS_SUCCESS;
            }

            // Second-chance / genuinely unhandled exception: nothing caught it -> fatal.
            c.win_emu.callbacks.on_exception();
            c.emu.stop();

            return STATUS_SUCCESS;
        }
    }

} // namespace sogen
