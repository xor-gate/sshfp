package main

import (
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

type SSHClient struct {
	key  []byte
	c    *ssh.Client
	host string
	cfg  *ssh.ClientConfig
}

func NewSSHClient(hkcb ssh.HostKeyCallback) *SSHClient {
	return &SSHClient{
		cfg: &ssh.ClientConfig{
			HostKeyCallback: hkcb,
		},
	}
}

func (c *SSHClient) SetPrivateKeyFromFile(filename string) error {
	key, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	pkey, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return err
	}
	c.cfg.Auth = []ssh.AuthMethod{
		ssh.PublicKeys(pkey),
	}
	return nil
}

func (c *SSHClient) Connect(user, host string) error {
	c.cfg.User = user
	sc, err := ssh.Dial("tcp", host, c.cfg)
	if err != nil {
		return err
	}
	c.c = sc
	return nil
}
