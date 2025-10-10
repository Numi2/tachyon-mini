 Qerkle Tree (qerkle) implements  cryptography to advance Merkle
Trees by dealing with hash selection and zero-knowledge proof check procedures. The methodology
incorporates long-term protection against  attacks together with operations that verify data
efficiently.
3.1. Hash Function Randomization
A dedicated dynamic hash selection mechanism enhances the unpredictability and 
security of the  Merkle Tree (qerkle). By using cryptographic random number
generators at each tree level, the system randomly alternates among SHAKE-256, Blake3, and Poseidon—
hash functions proven to resist Grover’s Algorithm-based attacks . This randomized structure
eliminates predictability, increasing entropy and mitigating risks from precomputed and collision-based
attacks. Moreover, if any hash function becomes vulnerable, the system can seamlessly switch to an
alternative, maintaining operational integrity. This multi-hash architecture significantly complicates the
attack surface, as adversaries cannot easily identify or exploit consistent cryptographic pathways. Thus,
qerkle ensures forward security and  adaptability, aligning with emerging cryptographic
standards for resilient data verification
3.2.  Tree Construction Algorithm
The qerkle framework establishes a protected tree framework that depends on scalable cryptography
technologies besides using logarithmic proof generation methodologies.
a) Step-by-Step Process for qerkle Construction The creation process for  Merkle Trees (qerkles) requires sequential protocols to
achieve both  security features and dynamic hashing applications and cryptographic
stability. Data transformation first encrypts data into cryptographic byte notations before these
cryptographically coded numbers are processed by hash functions, which make up SHAKE-256 and
Blake3, along with Poseidon. The standardization process turns information into an encrypted state before
it proceeds to cryptographic processing.
Dynamic hashing with  security comes into action at this point. The cryptographic
random number generator (CRNG) incorporated into each node level enables a dynamic process to select
hash functions. The randomization method chooses node pairs using cryptographic methods, and all three
hash functions (SHAKE-256, Blake3 and Poseidon) complete the procedure. The system implements this
step to eliminate dependency on a static hash function, which decreases the chance of future cryptographic
vulnerabilities appearing.
The structure uses two different modes for pairs but involves repeated duplication of the final node
at every level when the total quantity of nodes is not even. This maintains structural integrity. The way the
tree structure operates efficiently leads to no security or computational issues because this process makes
its structure uniform.
The process of iterative hashing generates one last Merkle root to serve as the cryptographic
fingerprint that summarizes the entire dataset. 


3.3. Encryption & Zero-Knowledge Proof-Based Verification
The security system of qerkle consists of two encryption layers that merge zk-STARKs proof
verification with the lattice-based encryption Kyber1024. The system protects encrypted metadata through
its combined approach between strong proof verification and metadata encryption.
3.3.1. Lattice-Based Encryption for Metadata Protection Units
Kyber1024 stands in as an RSA encryption replacement in qerkle to establish lattice encryption.

Kyber1024 within qerkle. 
essential information about running lattice-based encryption in qerkle. The Learning with Errors (LWE)
problem acts as the core functionality of Kyber1024 because  computers remain unable to solve it.
Key generation and encryption services within the system deliver secure solutions that maintain the
highest safety standards through effective procedures suitable for metadata protection.
3.3.2. Zero-Knowledge Proof Verification with zk-STARKs
The proof system uses zk-STARKs as zero-knowledge  proof technology for conducting
efficient trustless verification operations. The solution provided by zk-STARKs operates without trusted
setup procedures and pre-defined cryptographic keys, thus eliminating security threats from trusted
setups. The logarithmic proof verification mechanism operates to minimize computational overhead,
which enables high scalability of large-scale data structures. The confidentiality feature of zk-STARKs
allows users to verify Merkle roots while preventing the disclosure of private metadata and enhances the
authentication systems based on privacy protection.
The verification process in zk-SNARKs is a core feature that enables efficient proof validation without
revealing the underlying data. According to Bhaskar, once the prover generates a proof using the
structured reference string (SRS) and the witness (private inputs), the verifier can check the correctness of
the computation using the succinct proof and the public input. This verification requires significantly less
computational effort compared to re-executing the original computation. The succinctness ensures that the
size of the proof and the time to verify it remain constant, regardless of the complexity of the original
computation, which is critical for scalability and performance in blockchain and privacy-preserving
systems.

Secure Verification & Resistance to Unauthorized Tampering
Radanliev demonstrates how  cryptography can combine with artificial intelligence to boost
verification operations in qerkle through automated systems, according to his article [27]. qerkle operates
with complete security by enabling controlled access protocols along with encryption and verification
processes. The Kyber1024 private key serves as authorization only for authorized parties to authenticate
and decrypt encrypted metadata, thus securing the decryption process for  systems. The
verification process becomes invalidated if any unauthorized modifications occur to metadata because this
action safeguards both the qerkle structure and prevents tampering. The homomorphic encryption
framework proposed by Gentry [20] offers data verification enhancements through encrypted information
processing without decryption needs during verification operations. Using Kyber1024 encryption and zk-
STARKs verification together enables qerkle to establish a -secure verification framework for
distributed and blockchain systems.
4. Implementation Process
Implementing the  Merkle Tree (qerkle) integrates  cryptographic
techniques, dynamic hash function selection, and zero-knowledge proof verification, ensuring long-term
security and efficiency in data integrity verification. Below are the key components of the qerkle
framework.
4.1. Dynamic Hash Function Selection
qerkle leverages a cryptographic random number generator (CRNG) to dynamically select a post-
 secure hash. This approach produces cryptographic security using multiple different
cryptographic primitives.  hash operation SHAKE-256 stands as a NIST-standardized hash
function [4] and joins Blake3 as an optimized high-speed hashing solution [5] together with Poseidon,
which focuses on zk-STARKs and cryptographic proof optimization [6]. Randomized hashing strengthens
guesswork protection, which prevents pre-calculated  assault methods, including Grover’s
Algorithm-based collisions [7]. qerkle employs flexible cryptographic selection methods that make the
system resilient if a specific hash function falls under compromise [8].
4.2.  Lattice-Based Encryption with Kyber1024
The qerkle encryption system employs Kyber1024 as its encryption scheme
[2], [11]. Kyber1024 was selected among other candidates because its basis in the 
administrators about qerkle implementation in existing cryptographic systems. LWE decryption provides
effectiveness at key generation and cryptanalysis stages compared to RSA modes while maintaining
trustworthy  security standards, according to [9]. New Hope key exchange represents how
lattice-based cryptographic approaches, including Kyber1024, secure blockchain metadata successfull.The encryption system of Kyber1024 within qerkle ensures that Merkle root metadata,
along with selected hash function indices, maintains confidentiality against  attackers.
4.3. zk-STARKs for Trustless Proof Verification zero-knowledge proofs for blockchain systems and promotes zk-
STARKs as  verification protocols that match qerkle verification requirements. The
verification capability using zk-STARKs functions without requiring trust from either party. qerkle
establishes itself as the best method for blockchain integrity verification and protected distributed systems
verification.
4.4. Secure Metadata Encoding & Transmission
qerkle includes a sturdy encoding procedure that transmits metadata to various networks with both
speed and security. Base64 encoding provides a representation format for metadata by converting
encrypted metadata into text-based data, which protects transmission over networks [10]. All
unauthorized alterations to the qerkle structure are detected right away through tamper-resistant
cryptographic encoding [7]. Secure metadata encoding methods incorporated into qerkle ensure that both
data remain untainted and secure from unauthorized access during the communication of cryptographic
metadata.
4.5.  Security & Scalability
Fernandez-Carames and Fraga-Lamas deliver a full report about blockchain cryptography and its
resistance to  attacks, where they show the need for  schemes like qerkle.
qerkle acts as an essential element that enables blockchain connectivity with secure network protocols and
distributed data systems. The implementation adopts a strategy that both resists  threats and
allows the retention of current infrastructure components. The performance costs of cryptographic
procedures in qerkle remain low because the system implements advanced optimizations for quick proof
verification combined with fast hashing at optimal efficiency levels. The paper by [22] defines the 
computer challenges to blockchain cryptographic systems, which demonstrates the immediate need to use
qerkle for -secure distributed ledger networks.
By leveraging dynamic hash function selection, Kyber1024 encryption, and zk-STARK verification,
qerkle establishes a robust and forward-thinking framework for next-generation data integrity solutions.
5. Workflow
data.
Before constructing the Merkle Tree, we collect all the data blocks that must be securely hashed and
verified. Each data block represents information, such as transaction details, Each data block is hashed using a randomly selected  hash function. The available hash
functions include.
• SHAKE-256 (NIST  standard)
Blake3 (High-speed cryptographic hash)
• Poseidon (Optimized for zk-STARKs and blockchain verification)
A cryptographic random number generator (CRNG) selects one of these hash functions for each
hashing operation, ensuring unpredictability and security.Cryptographic Hashing Using a Randomized Hash Function
Once each data block is hashed, the algorithm assigns an index to the hashed output and stores it in a
new index array. This index keeps track of which hash function was used at each level, ensuring traceability
andtoring Hash Values in an Array-Based Index Structure
The algorithm proceeds to the next level by pairing adjacent hashed values, hashing them together,
and storing the new results at the next level of the tree.
Again, a random hash function is selected for each pairing. The process repeats at every level until
only one final root value remains.
PSEUDO CODE
#  Merkle Tree (qerkle) Implementation
#  cryptographic primitives:
# - SHAKE-256, Blake3, Poseidon for hashing
# - Kyber1024 for encryption
# - zk-STARKs for verification
# Global constants
HASH_FUNCTIONS = [SHAKE256, Blake3, Poseidon] #  hash
functions
SECURITY_PARAM = 256 # Security parameter in bits
def Buildqerkle(data_blocks):
"""
Constructs a  Merkle Tree from input data blocks
Args:
data_blocks: List of raw data blocks to be included in the tree
Returns:
Tuple: (encrypted_root, proof) where:
- encrypted_root: Kyber1024-encrypted Merkle root + indices
- proof: zk-STARK proof for verification
"""
# Phase 1: Leaf Node Construction
leaf_nodes = []
hash_indices = [] # Tracks hash functions used at each level
for block in data_blocks:
# Randomly select  hash function
hash_idx, hash_fn = RandomSelectHashFunction(HASH_FUNCTIONS)
# Store hash function index for verification
hash_indices.append(hash_idx)
# Hash data block with selected function
hashed_data = hash_fn(block, output_size=SECURITY_PARAM)
leaf_nodes.append(hashed_data)
# Phase 2: Tree Construction
current_level = leaf_nodes
level_hashes = [hash_indices.copy()] # Track hash indices per level
while len(current_level) > 1:
next_level = []
current_level_indices = []
for i in range(0, len(current_level), 2):
left_node = current_level[i]
right_node = current_level[i+1] if i+1 < len(current_level)
else left_node
# Random hash selection for this parent node
hash_idx, hash_fn = RandomSelectHashFunction(HASH_FUNCTIONS)
current_level_indices.append(hash_idx)
# Concatenate and hash child nodes
combined = left_node + right_node # Byte concatenation
parent_hash = hash_fn(combined, output_size=SECURITY_PARAM)
next_level.append(parent_hash)
current_level = next_level
level_hashes.append(current_level_indices)
ID : 950-0802/2025
Journal of Computing & Biomedical Informatics Volume 8 Issue 2
# Final Merkle root
merkle_root = current_level[0]
# Phase 3:  Protection
# Encrypt root and hash indices with Kyber1024
metadata = {
'root': merkle_root,
'hash_indices': level_hashes,
'timestamp': GetCurrentTime()
}
encrypted_data = Kyber1024_Encrypt(
plaintext=Serialize(metadata),
public_key=qerkle_PUBLIC_KEY
)
# Generate zk-STARK proof
proof = GenerateZkStarkProof(
merkle_root=merkle_root,
hash_indices=level_hashes,
security_param=SECURITY_PARAM
)
return (encrypted_data, proof)
def Verifyqerkle(encrypted_data, proof, data_block=None, position=None):
"""
Verifies a qerkle proof with optional membership check
Args:
encrypted_data: Kyber1024-encrypted root + indices
proof: zk-STARK proof
data_block: (Optional) Specific data block to verify
position: (Optional) Position of data block in tree
Returns:
bool: True if verification succeeds, False otherwise
"""
# Decrypt metadata with Kyber1024
try:
metadata = Deserialize(Kyber1024_Decrypt(
ciphertext=encrypted_data,
private_key=qerkle_PRIVATE_KEY
))
except DecryptionError:
return False
merkle_root = metadata['root']
level_hashes = metadata['hash_indices']
# Verify zk-STARK proof
if not VerifyZkStarkProof(proof, merkle_root):
return False
# Optional: Verify specific data block inclusion
if data_block is not None and position is not None:
if not VerifyMembership(
data_block,
position,
merkle_root,
level_hashes,
HASH_FUNCTIONS

---

Formulae Derivation
A. Hash Function Selection (Dynamic  Hashing)
• 𝐻 = { 𝐻₁, 𝐻₂, 𝐻₃ } = { 𝑆𝐻𝐴𝐾𝐸 − 256, 𝐵𝐿𝐴𝐾𝐸3, 𝑃𝑜𝑠𝑒𝑖𝑑𝑜𝑛 } be the set of available  secure
hash functions
• A cryptographic random number generator (CRNG) selects a hash function index 𝑖 ∈ {1, 2, 3}
• The selected hash function is 𝐻ᵢ ∈ 𝐻.
B. Hashing of Leaf Nodes
For each data block dⱼ, a randomly chosen hash function Hᵢ is applied:

𝐿ⱼ = 𝐻ᵢ(𝑑ⱼ)
Where:
• 𝐿ⱼ is the hashed leaf node.
• 𝑑ⱼ is the original data block.
• 𝐻ᵢ is selected using CRNG.
C. Parent Node Hashing
For each pair of child nodes A and B, the parent node P is computed as:
𝑃 = 𝐻ᵢ(𝐴 || 𝐵)
Where:
• 𝐴 || 𝐵 denotes the concatenation of two child node hashes.
• 𝐻ᵢ ∈ 𝐻 is the selected hash function for this level.
D. Merkle Root Computation
This recursive process continues until the final Merkle root R is obtained:
𝑅 = 𝐻ₖ(𝑃₁ || 𝑃₂)
Where:
• 𝑃₁, 𝑃₂, are the last remaining parent nodes
• 𝐻ₖ is the final randomly selected hash function.ds
E. Lattice-Based Encryption of Metadata (Kyber1024)
The Merkle root R and the hash function index array I⃗ are encrypted as follows:
𝐶 = 𝐾𝑦𝑏𝑒𝑟1024
_𝐸𝑛𝑐𝑟𝑦𝑝𝑡(𝑅, 𝐼⃗⃗)
Where:
• 𝑅 is the Merkle root.
• 𝐼⃗⃗ = [𝑖₁, 𝑖₂, . . . , 𝑖ₙ] represents the sequence of selected hash function indices.
• 𝐶 is the ciphertext output.
F. Zero-Knowledge Proof-Based Verification (zk-STARKs)
• To verify the integrity, decrypt C using the private key 𝑠𝑘:
(𝑅′
, 𝐼⃗⃗′) = 𝐾𝑦𝑏𝑒𝑟1024
_𝐷𝑒𝑐𝑟𝑦𝑝𝑡(𝐶, 𝑠𝑘)
• Recompute the Merkle root 𝑅′′ using 𝐼⃗⃗′ and the original data blocks.
• If 𝑅′
= 𝑅′′
, integrity is verified. Otherwise, integrity is compromised.
• A 𝑧𝑘 − 𝑆𝑇𝐴𝑅𝐾 proof π is generated:
𝜋 = 𝑆𝑇𝐴𝑅𝐾
_
𝑃𝑟𝑜𝑣𝑒(𝑑₁, 𝑑₂, . . . , 𝑑ₙ)
• And verified:
𝑆𝑇𝐴𝑅𝐾
_𝑉𝑒𝑟𝑖𝑓𝑦(𝜋) = True or False


-----


