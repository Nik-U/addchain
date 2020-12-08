package yacobi

import (
	"testing"

	"github.com/mmcloughlin/addchain/alg/contfrac"

	"github.com/mmcloughlin/addchain/alg/algtest"
)

func TestAlgorithm(t *testing.T) {
	seqalg := contfrac.NewAlgorithm(contfrac.BinaryStrategy{})
	a := NewAlgorithm(seqalg)
	algtest.ChainAlgorithm(t, a)
}
