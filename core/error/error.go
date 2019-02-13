package error

import "fmt"

const (
	CodeUnknown int = iota
	CodeParsingToken
)

type ParsingToken struct {
	Err error
}

func (err ParsingToken) Error() string {
	return fmt.Sprintf("error parsing token: %v", err.Err)
}

func (err ParsingToken) Message() string {
	return fmt.Sprintf("An internal error has occurred")
}

func (err ParsingToken) Code() int {
	return CodeParsingToken
}
