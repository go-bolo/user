package user_helpers

import "testing"

func TestValidateUsername(t *testing.T) {
	type args struct {
		username string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "success",
			args: args{
				username: "alberto",
			},
			want: true,
		},
		{
			name: "invalid",
			args: args{
				username: "alb ((",
			},
			want: false,
		},
		{
			name: "invalid space only",
			args: args{
				username: " ",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateUsername(tt.args.username); got != tt.want {
				t.Errorf("ValidateUsername() = %v, want %v", got, tt.want)
			}
		})
	}
}
