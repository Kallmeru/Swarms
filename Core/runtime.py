class AgentRuntime:
    def __init__(self, capability):
        self.capability = capability

    def run(self, agent_fn, input_value):
        # TODO: implement taint wrapping + capability drop
        return agent_fn(input_value)
