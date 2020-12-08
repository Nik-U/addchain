// Package yacobi implements the Yacobi chain generation algorithm.
package yacobi

import (
	"fmt"
	"math/big"

	"github.com/mmcloughlin/addchain/internal/bigints"

	"github.com/mmcloughlin/addchain/alg"

	"github.com/mmcloughlin/addchain/internal/bigint"

	"github.com/mmcloughlin/addchain"
)

// References:
//
//	[yacobi]  Yacobi, Y. Exponentiating Faster with Addition Chains. In Advances in Cryptology
//	          --- EUROCRYPT '90, pages 222--229. 1991.
//	          https://link.springer.com/content/pdf/10.1007/3-540-46877-3_20.pdf

// Algorithm implements Yacobi's chain generation algorithm described in [yacobi].
// This algorithm is a modification of the Lempel-Ziv data compression algorithm.
// The exponent is scanned from least to most significant bit (right-to-left) and
// a binary tree of symbols is constructed. These symbols form the basis for a
// dictionary. The given SequenceAlgorithm is used to build a chain for this
// dictionary. The exponent is then constructed according to the tree data, as
// shown in the exponents in Algorithm 1 [yacobi].
type Algorithm struct {
	seqalg alg.SequenceAlgorithm
}

// NewAlgorithm constructs a new ChainAlgorithm that uses the Yacobi method for
// generating chains. The given SequenceAlgorithm is used to construct the chain
// for the symbols.
func NewAlgorithm(a alg.SequenceAlgorithm) *Algorithm {
	return &Algorithm{seqalg: a}
}

// String returns a name for the algorithm.
func (a Algorithm) String() string { return fmt.Sprintf("yacobi(%s)", a.seqalg) }

// node is a tree node as described in [yacobi]. It is not necessary to store
// back pointers, nor is it necessary to store x^{e_k}, since we are just finding
// an addition chain and not actually exponentiating.
type node struct {
	e *big.Int // Extracted bits for this symbol.
	l uint     // The bit length. May be > e.BitLen() for leading zeroes.
	z uint     // The number of trailing zeroes when this symbol was first seen.

	childOne  *node // '1' branch of the tree.
	childZero *node // '0' branch of the tree.
}

// FindChain applies the Yacobi chain generation algorithm to the target.
func (a Algorithm) FindChain(target *big.Int) (addchain.Chain, error) {
	if !bigint.IsNonZero(target) {
		return addchain.Chain{}, nil
	}
	parses := a.buildTree(target)
	return a.deriveChain(parses)
}

// buildTree implements "subroutine build-tree" in [yacobi].
func (a Algorithm) buildTree(seq *big.Int) (parses []*node) {
	root := &node{e: bigint.One()}

	n := seq.BitLen()
	b := 0
	for b < n {
		z := uint(0)
		l := uint(0)

		for b < n && seq.Bit(b) == 0 {
			z++
			b++
		}
		if b >= n {
			break
		}

		start := b
		p := root
		var ns uint
		for {
			if b >= n {
				break
			}
			ns = seq.Bit(b)
			b++
			l++

			if ns == 0 {
				if p.childZero == nil {
					break
				}
				p = p.childZero
			} else {
				if p.childOne == nil {
					break
				}
				p = p.childOne
			}
		}
		end := b

		leaf := &node{
			e: bigint.Extract(seq, uint(start), uint(end)),
			z: z,
			l: l,
		}
		if ns == 0 {
			p.childZero = leaf
		} else {
			p.childOne = leaf
		}
		parses = append(parses, leaf)
	}
	return parses
}

// deriveChain generates the addition chain for the given output of buildTree.
// This is done by computing the combined exponent shown in Algorithm 1 in
// [yacobi].
func (a Algorithm) deriveChain(parses []*node) (addchain.Chain, error) {
	// Build the dictionary.
	dict := make([]*big.Int, 0, len(parses))
	for _, parse := range parses {
		dict = append(dict, parse.e)
	}
	bigints.Sort(dict)
	dict = bigints.Unique(dict)

	// Get a sequence that generates the dictionary values.
	c, err := a.seqalg.FindSequence(dict)
	if err != nil {
		return nil, err
	}

	// Construct the chain from left to right.
	x := new(big.Int)
	for i := len(parses) - 1; i >= 0; i-- {
		e := parses[i].e
		z := parses[i].z
		l := uint(0)
		if i > 0 {
			l = parses[i-1].l
		}

		// ... + e_i
		x.Add(x, e)
		c.AppendClone(x)

		// ... ) * 2^{z_i + Lᵢ₋₁}
		for j := uint(0); j < z+l; j++ {
			x.Lsh(x, 1)
			c.AppendClone(x)
		}
	}

	bigints.Sort(c)
	c = bigints.Unique(c)

	return c, nil
}
