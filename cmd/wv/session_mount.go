package main

func cmdMountComplete(args []string) int {
	routed, err := containsSessionPath(args)
	if err != nil {
		return mountArgumentError(err)
	}
	if routed {
		return cmdSessionMount(args)
	}
	return runVFSCommand(append([]string{"mount"}, args...))
}
