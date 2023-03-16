// Package hashmap implements a generic wrapper around a built in map type which allows
// interface types like PublicKeyHash to be used as map keys
package hashmap

import tz "github.com/ecadlabs/gotez"

type KV[K, V any] struct {
	Key K
	Val V
}

type HashMap[H tz.Comparable[K], K tz.ToComparable[H, K], V any] map[H]V

func (m HashMap[H, K, V]) Insert(key K, val V) (V, bool) {
	k := key.ToComparable()
	v, ok := m[k]
	m[k] = val
	return v, ok
}

func (m HashMap[H, K, V]) Get(key K) (V, bool) {
	k := key.ToComparable()
	v, ok := m[k]
	return v, ok
}

func (m HashMap[H, K, V]) ForEach(cb func(key K, val V) bool) {
	for k, v := range m {
		if !cb(k.ToKey(), v) {
			break
		}
	}
}

func New[H tz.Comparable[K], K tz.ToComparable[H, K], V any](init []KV[K, V]) HashMap[H, K, V] {
	m := make(HashMap[H, K, V])
	for _, kv := range init {
		m.Insert(kv.Key, kv.Val)
	}
	return m
}
