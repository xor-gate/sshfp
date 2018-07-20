package main

import (
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

// SSHClient is a wrapper for ssh.Client
type SSHClient struct {
	c   *ssh.Client
	cfg *ssh.ClientConfig
}

// NewSSHClient creates a new SSH client with custom ssh.HostKeyCallback
func NewSSHClient(hkcb ssh.HostKeyCallback) *SSHClient {
	return &SSHClient{
		cfg: &ssh.ClientConfig{
			HostKeyCallback: hkcb,
		},
	}
}

// SetPrivateKeyFromFile loads the public key from the private key
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

// Connect to the given user on host
func (c *SSHClient) Connect(user, host string) error {
	c.cfg.User = user
	sc, err := ssh.Dial("tcp", host, c.cfg)
	if err != nil {
		return err
	}
	c.c = sc
	return nil
}
