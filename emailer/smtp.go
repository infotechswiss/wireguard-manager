package emailer

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	mail "github.com/xhit/go-simple-mail/v2"
)

// SmtpMail implements the Emailer interface using an SMTP server.
type SmtpMail struct {
	hostname   string
	port       int
	username   string
	password   string
	smtpHelo   string
	authType   mail.AuthType
	encryption mail.Encryption
	noTLSCheck bool
	fromName   string
	from       string
}

// authType converts a string to the corresponding mail.AuthType.
func authType(authTypeStr string) mail.AuthType {
	switch strings.ToUpper(authTypeStr) {
	case "PLAIN":
		return mail.AuthPlain
	case "LOGIN":
		return mail.AuthLogin
	default:
		return mail.AuthNone
	}
}

// encryptionType converts a string to the corresponding mail.Encryption.
func encryptionType(encryptionTypeStr string) mail.Encryption {
	switch strings.ToUpper(encryptionTypeStr) {
	case "NONE":
		return mail.EncryptionNone
	case "SSL":
		return mail.EncryptionSSL
	case "SSLTLS":
		return mail.EncryptionSSLTLS
	case "TLS":
		return mail.EncryptionTLS
	default:
		return mail.EncryptionSTARTTLS
	}
}

// NewSmtpMail returns a new instance of SmtpMail configured with the provided parameters.
func NewSmtpMail(hostname string, port int, username string, password string, smtpHelo string, noTLSCheck bool, auth string, fromName, from string, encryption string) *SmtpMail {
	return &SmtpMail{
		hostname:   hostname,
		port:       port,
		username:   username,
		password:   password,
		smtpHelo:   smtpHelo,
		noTLSCheck: noTLSCheck,
		fromName:   fromName,
		from:       from,
		authType:   authType(auth),
		encryption: encryptionType(encryption),
	}
}

// addressField formats an email address with an optional display name.
func addressField(address, name string) string {
	if name == "" {
		return address
	}
	return fmt.Sprintf("%s <%s>", name, address)
}

// Send sends an email with the specified details and attachments via SMTP.
func (s *SmtpMail) Send(toName, to, subject, content string, attachments []Attachment) error {
	server := mail.NewSMTPClient()
	server.Host = s.hostname
	server.Port = s.port
	server.Authentication = s.authType
	server.Username = s.username
	server.Password = s.password
	server.Helo = s.smtpHelo
	server.Encryption = s.encryption
	server.KeepAlive = false
	server.ConnectTimeout = 10 * time.Second
	server.SendTimeout = 10 * time.Second

	// If noTLSCheck is true, skip TLS certificate verification.
	if s.noTLSCheck {
		server.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}

	smtpClient, err := server.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}

	email := mail.NewMSG()
	email.SetFrom(addressField(s.from, s.fromName)).
		AddTo(addressField(to, toName)).
		SetSubject(subject).
		SetBody(mail.TextHTML, content)

	// Attach files, if any.
	for _, att := range attachments {
		email.Attach(&mail.File{
			Name: att.Name,
			Data: att.Data,
		})
	}

	if err := email.Send(smtpClient); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}
