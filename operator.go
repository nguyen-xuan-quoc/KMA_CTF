package main

import (
	"crypto/rand"
	"math/big"
)

type (
	// voter will submit votes
	voter struct {
		poly  []*big.Int
		agree bool
		votes []*big.Int
	}

	// authority will count the votes
	authority struct {
		id    *big.Int
		votes []*big.Int
	}
)

// random polynomial of degree d
func init_voter(d int, agree bool) *voter {
	poly := make([]*big.Int, d+1)
	poly[0] = big.NewInt(0)
	if agree {
		poly[0] = big.NewInt(1)
	}

	for i := 1; i <= d; i++ {
		buf := make([]byte, 32)
		rand.Read(buf)
		poly[i] = new(big.Int).SetBytes(buf)
	}
	return &voter{poly: poly, agree: agree}
}

func init_authority() *authority {
	buf := make([]byte, 32)
	rand.Read(buf)
	return &authority{id: new(big.Int).SetBytes(buf)}
}

func (voter *voter) eval(authority_id *big.Int) *big.Int {
	p := new(big.Int).SetBytes([]byte{255, 255, 255, 255, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255})
	vote := big.NewInt(0)  // = 0
	id := big.NewInt(1) // = 1
	for _, coef := range voter.poly {
		tmp := new(big.Int).Mul(coef, id)
		vote.Add(vote, tmp)
		id.Mul(id, authority_id)
		id.Mod(id, p)
		// vote = sum(coef[i]*id[i]), id[i] = authority_id^i
	}
	vote.Mod(vote, p)
	return vote
}

func (authority *authority) count_votes() *big.Int {
	p := new(big.Int).SetBytes([]byte{255, 255, 255, 255, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255})
	result := big.NewInt(0)
	for _, vote := range authority.votes {
		result.Add(result, vote)
	}
	result.Mod(result, p) // f1(x) + f2(x) + ... + f9(x) = g(x)
	return result
}

func get_ids(authorities []*authority) []*big.Int {
	ids := make([]*big.Int, len(authorities))
	for i := 0; i < len(authorities); i++ {
		ids[i] = authorities[i].id
	}
	return ids
}

func get_votes(authorities []*authority) []*big.Int {
	votes := make([]*big.Int, len(authorities))
	for i := 0; i < len(authorities); i++ {
		votes[i] = authorities[i].count_votes() //f0(id[i]) + f1(id[i]) + ... + f9(id[i]) = g(id[i])
	}
	return votes //list of vote
}

//(id, votes)-> (x, y)
func lagrange_interpolate(ids, votes []*big.Int) *big.Int {
	p := new(big.Int).SetBytes([]byte{255, 255, 255, 255, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255})
	if len(ids) != len(votes) {
		return nil
	}
	sum := big.NewInt(0) //sum = 0
	for i := 0; i < len(votes); i++ {
		tmp := votes[i] // votes of authorities[i]
		for j := 0; j < len(ids); j++ {
			if i != j {
				neg := new(big.Int).Neg(ids[j]) // -id[j]
				neg.Add(neg, p) //(p-id[j])
				tmp.Mul(tmp, neg) // (votes[i]*(p-id[j]))
				neg.Add(neg, ids[i]) //(p-id[j]+id[i])
				neg.ModInverse(neg, p) //(p-id[j]+id[i])^-1 % p
				tmp.Mul(tmp, neg)
			}
		}
		sum.Add(sum, tmp)
		sum.Mod(sum, p)
	}
	return sum
}
