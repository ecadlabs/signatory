package utils

import (
	"fmt"
	"reflect"
	"strconv"
)

type Options map[string]interface{}

func (o Options) GetString(name string) (val string, ok bool, err error) {
	v, ok := o[name]
	if !ok {
		return "", false, nil
	}

	switch vv := v.(type) {
	case string:
		return vv, true, nil
	default:
		return fmt.Sprintf("%v", v), true, nil
	}
}

func getInt(v interface{}) int64 {
	val := reflect.ValueOf(v)

	switch val.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return val.Int()

	case reflect.Float32, reflect.Float64:
		return int64(val.Float())
	}

	return 0
}

func (o Options) GetInt(name string) (val int64, ok bool, err error) {
	v, ok := o[name]
	if !ok {
		return 0, false, nil
	}

	if s, ok := v.(string); ok {
		i, err := strconv.ParseInt(s, 0, 64)
		return i, true, err
	}

	return getInt(v), true, nil
}

func (o Options) GetBool(name string) (val bool, ok bool, err error) {
	v, ok := o[name]
	if !ok {
		return false, false, nil
	}

	switch vv := v.(type) {
	case bool:
		return vv, true, nil
	case string:
		b, err := strconv.ParseBool(vv)
		return b, true, err
	default:
		if getInt(v) != 0 {
			return true, true, nil
		}
		return false, true, nil
	}
}
