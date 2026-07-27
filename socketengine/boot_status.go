package socketengine

// BootError returns a listener/bootstrap error recorded before the engine
// entered its ready state. A nil result means OnBoot completed successfully.
func (e *Engine) BootError() error {
	if e == nil {
		return nil
	}
	return e.getBootError()
}
