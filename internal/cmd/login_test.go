package cmd

import "testing"

func TestForceFreshLogin(t *testing.T) {
	tests := []struct {
		name             string
		globalForceLogin bool
		loginForce       bool
		want             bool
	}{
		{name: "no force flags", want: false},
		{name: "login force flag", loginForce: true, want: true},
		{name: "global force login flag", globalForceLogin: true, want: true},
		{name: "both force flags", globalForceLogin: true, loginForce: true, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := forceFreshLogin(tt.globalForceLogin, tt.loginForce); got != tt.want {
				t.Errorf("forceFreshLogin(%t, %t) = %t, want %t", tt.globalForceLogin, tt.loginForce, got, tt.want)
			}
		})
	}
}
