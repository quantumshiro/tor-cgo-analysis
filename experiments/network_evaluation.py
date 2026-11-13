"""Small isolated C Tor network for cross-build memory-forensics evaluation."""

parent = Node()

authority = parent.specialize(tag="a", authority=1, relay=1)
parent.launch_phase += 1
relay = parent.specialize(tag="r", relay=1, exit=1)
client = parent.specialize(tag="c", client=1)

NODES = authority.getN(4) + relay.getN(2) + client.getN(1)

ConfigureNodes(NODES)
