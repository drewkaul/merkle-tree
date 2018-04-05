from utils import *
import math
from node import Node


def merkle_proof(tx, merkle_tree):
    """Given a tx and a Merkle tree object, retrieve its list of tx's and
    parse through it to arrive at the minimum amount of information required
    to arrive at the correct block header. This does not include the tx
    itself.

    Return this data as a list; remember that order matters!
    """
    proof = []
    tx_ind = merkle_tree.leaves.index(tx)
    node = merkle_tree._root
    
    lower = 0
    upper = len(merkle_tree.leaves)
    depth = 1

    while upper - lower > 1:
        mid = (lower + upper) // 2
        if tx_ind >= mid:
            if type(node._left) != str:
                proof.append(Node(depth, "l", node._left.data))
            else:
                proof.append(Node(depth, "l", node._left))
            lower = mid
            node = node._right
        else:
            if type(node._right) != str:
                proof.append(Node(depth, "r", node._right.data))
            else:
                proof.append(Node(depth, "r", node._right))
            upper = mid
            node = node._left
        depth += 1
    return proof


def get_max_depth_node(nodes):
    """Helper function to retrieve the node with the maximum depth.
    Helpful for pairing nodes for hashing in verify_proof"""
    curr = nodes[0]
    for i in range(0, len(nodes)):
        if nodes[i].depth > curr.depth:
            curr = nodes[i]
    return curr


def verify_proof(tx, merkle_proof):
    """Given a Merkle proof - constructed via `merkle_proof(...)` - verify
    that the correct block header can be retrieved by properly hashing the tx
    along with every other piece of data in the proof in the correct order
    """
    data = tx
    proof = merkle_proof[::-1]
    for i in range(0, len(proof)):
        if proof[i].direction == 'l':
            data = hash_data(proof[i].tx + data)
        elif proof[i].direction == 'r':
            data = hash_data(data + proof[i].tx)
    return data


    
