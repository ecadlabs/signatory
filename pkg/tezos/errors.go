package tezos

import "fmt"

// MessageTooShortError is an error indicating that a message is too short
type MessageTooShortError struct {
	Len int
}

// Error implements error interface
func (m *MessageTooShortError) Error() string {
	return fmt.Sprintf("Invalid message length: %d", m.Len)
}

// MagicByteError is an error indicating that a message magic byte is invalid
type MagicByteError struct {
	Value int
}

// Error implements error interface
func (m *MagicByteError) Error() string {
	return fmt.Sprintf("Invalid magic byte: %#02x", m.Value)
}

// MessageKindError is an error indicating that a message kind code is invalide
type MessageKindError struct {
	Value int
}

// Error implements error interface
func (m *MessageKindError) Error() string {
	return fmt.Sprintf("Invalid kind code: %#02x", m.Value)
}

// FilterError indicates that message is rejected by the filter
type FilterError struct {
	// TODO
}

// Error implements error interface
func (f *FilterError) Error() string {
	return "Operation not permitted by filter"
}
