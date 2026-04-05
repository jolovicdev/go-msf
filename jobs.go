package gomsf

import (
	"context"
	"fmt"
)

type JobManager struct {
	rpc RPCCaller
}

func NewJobManager(rpc RPCCaller) *JobManager {
	return &JobManager{rpc: rpc}
}

func (m *JobManager) List(ctx context.Context) (map[string]string, error) {
	result, err := m.rpc.Call(ctx, JobList)
	if err != nil {
		return nil, err
	}

	jobs, err := responseMap(result)
	if err != nil {
		return nil, err
	}

	jobMap := make(map[string]string, len(jobs))
	for k, v := range jobs {
		value, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%w: expected job %s string", ErrUnexpectedResponse, k)
		}
		jobMap[k] = value
	}

	return jobMap, nil
}

func (m *JobManager) Stop(ctx context.Context, jobID string) error {
	_, err := m.rpc.Call(ctx, JobStop, jobID)
	if err != nil && rpcErrorMessage(err, "Invalid Job") {
		return fmt.Errorf("%w: %s", ErrJobNotFound, jobID)
	}
	return err
}

func (m *JobManager) Info(ctx context.Context, jobID string) (map[string]interface{}, error) {
	result, err := m.rpc.Call(ctx, JobInfo, jobID)
	if err != nil {
		if rpcErrorMessage(err, "Invalid Job") {
			return nil, fmt.Errorf("%w: %s", ErrJobNotFound, jobID)
		}
		return nil, err
	}

	return responseMap(result)
}
