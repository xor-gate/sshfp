// Package sshfp implements a ssh.HostKeyCallback for resolving SSH host key fingerprints using DNS
//
// Overview
//
// The most basic debian package is created as follows (without error checking):
//
//  r := sshfp.NewResolver(sshfp.WithDNSClientConfigFromFile("/etc/resolv.conf"))
//
//  sshClientConfig := &ssh.ClientConfig{
//      HostKeyCallback: r.HostKeyCallback,
//  }
//
//  c, err := ssh.Dial("tcp", "remote.example.org:22", sshClientConfig)
//  ... Check error and do something with the SSHFP validated connected client

package sshfp
