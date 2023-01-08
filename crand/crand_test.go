// These tests have been copied from the tests in math/rand. Purpose was to
// test the distribution and that the tests pass with the same sample size
// (10000 samples), the same mean (0) and the same standard deviation (1). They
// do not currently cover all frontend functions, but the backend Uint64 is
// fully covered.

package crand

import (
	"errors"
	"fmt"
	"math"
	"testing"
)

const (
	numTestSamples = 10000
)

type statsResults struct {
	mean        float64
	stddev      float64
	closeEnough float64
	maxError    float64
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func nearEqual(a, b, closeEnough, maxError float64) bool {
	absDiff := math.Abs(a - b)
	if absDiff < closeEnough { // Necessary when one value is zero and one value is close to zero.
		return true
	}
	return absDiff/max(math.Abs(a), math.Abs(b)) < maxError
}

func (this *statsResults) checkSimilarDistribution(expected *statsResults) error {
	if !nearEqual(this.mean, expected.mean, expected.closeEnough, expected.maxError) {
		s := fmt.Sprintf("mean %v != %v (allowed error %v, %v)", this.mean, expected.mean, expected.closeEnough, expected.maxError)
		fmt.Println(s)
		return errors.New(s)
	}
	if !nearEqual(this.stddev, expected.stddev, expected.closeEnough, expected.maxError) {
		s := fmt.Sprintf("stddev %v != %v (allowed error %v, %v)", this.stddev, expected.stddev, expected.closeEnough, expected.maxError)
		fmt.Println(s)
		return errors.New(s)
	}
	return nil
}

func getStatsResults(samples []float64) *statsResults {
	res := new(statsResults)
	var sum, squaresum float64
	for _, s := range samples {
		sum += s
		squaresum += s * s
	}
	res.mean = sum / float64(len(samples))
	res.stddev = math.Sqrt(squaresum/float64(len(samples)) - res.mean*res.mean)
	return res
}
func checkSampleDistribution(t *testing.T, samples []float64, expected *statsResults) {
	t.Helper()
	actual := getStatsResults(samples)
	err := actual.checkSimilarDistribution(expected)
	if err != nil {
		t.Error(err.Error())
	}
}
func checkSampleSliceDistributions(t *testing.T, samples []float64, nslices int, expected *statsResults) {
	t.Helper()
	chunk := len(samples) / nslices
	for i := 0; i < nslices; i++ {
		low := i * chunk
		var high int
		if i == nslices-1 {
			high = len(samples) - 1
		} else {
			high = (i + 1) * chunk
		}
		checkSampleDistribution(t, samples[low:high], expected)
	}
}

func generateNormalSamples(nsamples int, mean, stddev float64) []float64 {
	samples := make([]float64, nsamples)
	for i := range samples {
		samples[i] = gr.NormFloat64()*stddev + mean
	}
	return samples
}

func testNormalDistribution(t *testing.T, nsamples int, mean, stddev float64) {
	samples := generateNormalSamples(nsamples, mean, stddev)
	zeroes := 0
	for i := range samples {
		if samples[i] == 0 {
			zeroes++
		}
	}
	if zeroes == len(samples) {
		t.Error("Samples appear to be uninitialized, they are all zeroes, expected much less")
	} else if zeroes > len(samples)/2 {
		t.Errorf("There are %d zereos in the samples, expected less than %d", zeroes, len(samples)/2)
	}
	errorScale := max(1.0, stddev)
	expected := &statsResults{mean, stddev, 0.10 * errorScale, 0.08 * errorScale}
	checkSampleDistribution(t, samples, expected)
	checkSampleSliceDistributions(t, samples, 2, expected)
	checkSampleSliceDistributions(t, samples, 7, expected)
}

func TestStandardNormalValues(t *testing.T) {
	testNormalDistribution(t, numTestSamples, 0, 1)
}
