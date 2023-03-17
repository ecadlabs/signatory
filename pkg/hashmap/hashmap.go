// Package hashmap implements a generic wrapper around a built in map type which allows
// interface types like PublicKeyHash to be used as map keys
package hashmap

import tz "github.com/ecadlabs/gotez"

type KV[K, V any] struct {
	Key K
	Val V
}

// HashMap is a wrapper around a built in map type which allows interface types
// like gotez.PublicKeyHash to be used as map keys
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

func (m HashMap[H, K, V]) ForEach(cb func(key K, val V) bool) bool {
	for k, v := range m {
		if !cb(k.ToKey(), v) {
			return false
		}
	}
	return true
}

func New[H tz.Comparable[K], K tz.ToComparable[H, K], V any](init []KV[K, V]) HashMap[H, K, V] {
	m := make(HashMap[H, K, V])
	for _, kv := range init {
		m.Insert(kv.Key, kv.Val)
	}
	return m
}

// PublicKeyHashMap is a shortcut for a map with gotez.PublicKeyHash keys
type PublicKeyHashMap[V any] HashMap[tz.EncodedPublicKeyHash, tz.PublicKeyHash, V]

func NewPublicKeyHashMap[V any](init []KV[tz.PublicKeyHash, V]) PublicKeyHashMap[V] {
	return PublicKeyHashMap[V](New[tz.EncodedPublicKeyHash](init))
}

func (m PublicKeyHashMap[V]) Insert(key tz.PublicKeyHash, val V) (V, bool) {
	return HashMap[tz.EncodedPublicKeyHash, tz.PublicKeyHash, V](m).Insert(key, val)
}

func (m PublicKeyHashMap[V]) Get(key tz.PublicKeyHash) (V, bool) {
	return HashMap[tz.EncodedPublicKeyHash, tz.PublicKeyHash, V](m).Get(key)
}

func (m PublicKeyHashMap[V]) ForEach(cb func(key tz.PublicKeyHash, val V) bool) bool {
	return HashMap[tz.EncodedPublicKeyHash, tz.PublicKeyHash, V](m).ForEach(cb)
}
