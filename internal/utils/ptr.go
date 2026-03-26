package utils

func Ptr[T any](v T) *T {
	return &v
}

func StringValue(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
