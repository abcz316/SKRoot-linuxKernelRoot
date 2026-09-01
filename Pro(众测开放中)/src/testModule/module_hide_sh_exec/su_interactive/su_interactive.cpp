#include "su_interactive.h"

#include "pipe_su_interactive.h"
#include "pty_su_interactive.h"

const char* su_interactive_mode_name(SuInteractiveMode mode) {
    return mode == SuInteractiveMode::Pipe ? "pipe" : "pty";
}

SuInteractiveMode su_interactive_mode_from_name(std::string_view name) {
    return name == "pipe" ? SuInteractiveMode::Pipe : SuInteractiveMode::Pty;
}

std::unique_ptr<ISuInteractive> createSuInteractive(SuInteractiveMode mode) {
    switch (mode) {
        case SuInteractiveMode::Pipe:
            return std::make_unique<PipeSuInteractive>();
        case SuInteractiveMode::Pty:
        default:
            return std::make_unique<PtySuInteractive>();
    }
}

SuInteractive::SuInteractive(SuInteractiveMode mode)
    : m_mode(mode)
    , m_impl(createSuInteractive(mode)) {}

SuInteractive::~SuInteractive() = default;

bool SuInteractive::start(std::string_view shell_rc_dir) {
    return m_impl->start(shell_rc_dir);
}

bool SuInteractive::send(const std::string& s) {
    return m_impl->send(s);
}

bool SuInteractive::sendLine(const std::string& line) {
    return m_impl->sendLine(line);
}

void SuInteractive::closeInput() {
    m_impl->closeInput();
}

int SuInteractive::wait() {
    return m_impl->wait();
}

void SuInteractive::stop(bool force) {
    m_impl->stop(force);
}

std::string SuInteractive::output() const {
    return m_impl->output();
}

std::string SuInteractive::takeOutput() {
    return m_impl->takeOutput();
}

pid_t SuInteractive::get_shell_pid() {
    return m_impl->get_shell_pid();
}

bool SuInteractive::isShellForeground() const {
    return m_impl->isShellForeground();
}

SuInteractiveMode SuInteractive::mode() const {
    return m_mode;
}
