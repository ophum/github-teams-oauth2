package server

import (
	"net/url"
	"reflect"
	"testing"
)

func Test_validateRedirectURI(t *testing.T) {
	type args struct {
		redirectURI string
		validURIs   []string
	}
	wantURL := &url.URL{
		Scheme: "http",
		Host:   "localhost:8081",
		Path:   "/callback",
	}
	tests := []struct {
		name    string
		args    args
		want    *url.URL
		wantErr bool
	}{
		{
			name: "validURIsが指定されていないときredirect_uriが必須",
			args: args{
				redirectURI: "http://localhost:8081/callback",
				validURIs:   []string{},
			},
			want:    wantURL,
			wantErr: false,
		},
		{
			// 不正なurlとは? url.Parseだと適当な文字列でも通る
			name: "validURIsが指定されていないときredirect_uriが必須,不正なuriの場合エラー",
			args: args{
				redirectURI: "",
				validURIs:   []string{},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "validURIsが1つだけでredirect_uriが指定されていないときはvalidURIs[0]",
			args: args{
				redirectURI: "",
				validURIs:   []string{"http://localhost:8081/callback"},
			},
			want:    wantURL,
			wantErr: false,
		},
		{
			name: "validURIsのうちの1つとredirect_uriが一致する",
			args: args{
				redirectURI: "http://localhost:8081/callback",
				validURIs: []string{
					"http://localhost:8081/callback",
					"http://localhost:8082/callback",
				},
			},
			want:    wantURL,
			wantErr: false,
		},
		{
			name: "validURIsのうちの1つとredirect_uriが一致する,部分一致",
			args: args{
				redirectURI: "http://localhost:8081/callback",
				validURIs: []string{
					"http://localhost:8081/",
					"http://localhost:8082/callback",
				},
			},
			want:    wantURL,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateRedirectURI(tt.args.redirectURI, tt.args.validURIs)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRedirectURI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("validateRedirectURI() = %v, want %v", got, tt.want)
			}
		})
	}
}
