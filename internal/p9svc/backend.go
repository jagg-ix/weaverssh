package p9svc

import (
	"errors"
	"sync"

	"weaverssh/filebackend"
)

var configuredBackends sync.Map

// SetBackendAPI associates a file backend controller with a 9P server. Dynamic
// ServiceFS transports use it for hooks and durable core state without changing
// the 9P2000 wire protocol.
func SetBackendAPI(server *Server, backend filebackend.API) error {
	if server == nil {
		return errors.New("p9svc: nil server")
	}
	if backend == nil {
		configuredBackends.Delete(server)
		return nil
	}
	configuredBackends.Store(server, backend)
	return nil
}

func BackendDescription(server *Server) filebackend.Description {
	if backend := backendAPI(server); backend != nil {
		return backend.Describe()
	}
	return filebackend.Description{}
}

func backendAPI(server *Server) filebackend.API {
	if server == nil {
		return nil
	}
	value, ok := configuredBackends.Load(server)
	if !ok {
		return nil
	}
	backend, _ := value.(filebackend.API)
	return backend
}
