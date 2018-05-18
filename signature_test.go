package goethauth

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func Test_IsMsgSignedByEthAccount(t *testing.T) {
	type args struct {
		ethAccountStr string
		msg           string
		sigStr        string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "valid signature and account",
			args: args{
				ethAccountStr: "0xa26f2b342aab24bcf63ea218c6a9274d30ab9a16",
				msg:           "NO_PRODUCTION_CHALLENGE",
				sigStr: "0xa226068b85f311996530599beabe5ba67036b4cd2362" +
					"660f6b959c74d6474c2a0f8fb5504aad06054f641d9a5d6fd5c" +
					"25d6ea5eb6edce5f2f02bd10c509bb1c51c",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "valid signature and account with no 0x",
			args: args{
				ethAccountStr: "a26f2b342aab24bcf63ea218c6a9274d30ab9a16",
				msg:           "NO_PRODUCTION_CHALLENGE",
				sigStr: "0xa226068b85f311996530599beabe5ba67036b4cd236" +
					"2660f6b959c74d6474c2a0f8fb5504aad06054f641d9a5d6f" +
					"d5c25d6ea5eb6edce5f2f02bd10c509bb1c51c",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "account too short",
			args: args{
				ethAccountStr: "a26f2b342aab24bcf63ea218c6a9274d30ab9a1",
				msg:           "NO_PRODUCTION_CHALLENGE",
				sigStr: "0xa226068b85f311996530599beabe5ba67036b4" +
					"cd2362660f6b959c74d6474c2a0f8fb5504aad06054f641d9" +
					"a5d6fd5c25d6ea5eb6edce5f2f02bd10c509bb1c51c",
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "shorter signature",
			args: args{
				ethAccountStr: "a26f2b342aab24bcf63ea218c6a9274d30ab9a16",
				msg:           "NO_PRODUCTION_CHALLENGE",
				sigStr: "0xa22068b85f311996530599beabe5ba67036b" +
					"4cd2362660f6b959c74d6474c2a0f8fb5504aad06054f641d9a5d6" +
					"fd5c25d6ea5eb6edce5f2f02bd10c509bb1c51c",
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "signature not hex",
			args: args{
				ethAccountStr: "a26f2b342aab24bcf63ea218c6a9274d30ab9a16",
				msg:           "NO_PRODUCTION_CHALLENGE",
				sigStr: "0xa22R068b85f311996530599beabe5ba67036b4cd236" +
					"2660f6b959c74d6474c2a0f8fb5504aad06054f641" +
					"d9a5d6fd5c25d6ea5eb6edce5f2f02bd10c509bb1c51c",
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "wrong sig",
			args: args{
				ethAccountStr: "a26f2b342aab24bcf63ea218c6a9274d30ab9a16",
				msg:           "NO_PRODUCTION_CHALLENGE",
				sigStr: "0xa226018b85f311996530599beabe5ba67036b4cd236" +
					"2660f6b959c74d6474c2a0f8fb5504aad06054f641d9a5d6" +
					"fd5c25d6ea5eb6edce5f2f02bd10c509bb1c51c",
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "not hex account submitted",
			args: args{
				ethAccountStr: "aR6f2b342aab24bcf63ea218c6a9274d30ab9a16",
				msg:           "NO_PRODUCTION_CHALLENGE",
				sigStr: "0xa226018b85f311996530599beabe5ba67036b4cd" +
					"2362660f6b959c74d6474c2a0f8fb5504aad0" +
					"6054f641d9a5d6fd5c25d6ea5eb6edce5f2f02bd10c509bb1c51c",
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "account submitted not matching the sig one",
			args: args{
				ethAccountStr: "a26e2b342aab24bcf63ea218c6a9274d30ab9a16",
				msg:           "NO_PRODUCTION_CHALLENGE",
				sigStr: "0xa226068b85f311996530599beabe5ba67036b4cd23" +
					"62660f6b959c74d6474c2a0f8fb5504aad06" +
					"054f641d9a5d6fd5c25d6ea5eb6edce5f2f02bd10c509bb1c51c",
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "empty signature",
			args: args{
				ethAccountStr: "a26e2b342aab24bcf63ea218c6a9274d30ab9a16",
				msg:           "NO_PRODUCTION_CHALLENGE",
				sigStr:        "",
			},
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsMsgSignedByEthAccount(tt.args.ethAccountStr,
				tt.args.msg, tt.args.sigStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsMsgSignedByEthAccount() error = %v, wantErr %v",
					err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IsMsgSignedByEthAccount() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHashEthereumMessage(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want string
	}{
		{
			name: "Hash message",
			msg:  "🦄",
			want: "714436f28d7d871df2fce3ce77" +
				"6c0bead83ad0735b07534d0ad4c880ca5b7171",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HashEthereumMessage(tt.msg)
			wantB, _ := hex.DecodeString(tt.want)
			if !reflect.DeepEqual(got, wantB) {
				t.Errorf("HashEthereumMessage() = 0x%x, want 0x%x",
					got,
					wantB,
				)
			}
		})
	}
}

func Test_CleanSig(t *testing.T) {
	tests := []struct {
		name string
		sigB []byte
		want []byte
	}{
		{
			name: "sig with no 1c or 1b",
			sigB: []byte{0x00, 0x01, 0x02},
			want: []byte{0x00, 0x01, 0x02},
		},
		{
			name: "sig with 1b",
			sigB: []byte{0x00, 0x01, 0x1b},
			want: []byte{0x00, 0x01, 0x00},
		},
		{
			name: "sig with 1c",
			sigB: []byte{0x00, 0x01, 0x1c},
			want: []byte{0x00, 0x01, 0x01},
		},
		{
			name: "sig with len 1",
			sigB: []byte{0x00},
			want: []byte{0x00},
		},
		{
			name: "sig with len 0",
			sigB: []byte{},
			want: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CleanSig(tt.sigB); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CleanSig() = 0x%x, want 0x%x", got, tt.want)
			}
		})
	}
}
