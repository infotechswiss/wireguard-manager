package emailer

import (
	"encoding/base64"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// SendgridApiMail implements the Emailer interface using SendGrid's API.
type SendgridApiMail struct {
	apiKey   string
	fromName string
	from     string
}

// NewSendgridApiMail creates a new SendgridApiMail instance with the provided API key and sender information.
func NewSendgridApiMail(apiKey, fromName, from string) *SendgridApiMail {
	return &SendgridApiMail{
		apiKey:   apiKey,
		fromName: fromName,
		from:     from,
	}
}

// Send sends an email using the SendGrid API.
// It builds a V3Mail object with the given recipient details, subject, content, and attachments.
func (s *SendgridApiMail) Send(toName, to, subject, content string, attachments []Attachment) error {
	m := mail.NewV3Mail()

	// Set sender, recipient, content, and subject.
	mailFrom := mail.NewEmail(s.fromName, s.from)
	mailTo := mail.NewEmail(toName, to)
	m.SetFrom(mailFrom)
	m.AddContent(mail.NewContent("text/html", content))

	personalization := mail.NewPersonalization()
	personalization.AddTos(mailTo)
	personalization.Subject = subject
	m.AddPersonalizations(personalization)

	// Process attachments.
	var sgAttachments []*mail.Attachment
	for _, a := range attachments {
		encoded := base64.StdEncoding.EncodeToString(a.Data)
		sgAtt := mail.NewAttachment()
		sgAtt.SetContent(encoded)
		// Set a default content type. Adjust if you need to support other file types.
		sgAtt.SetType("text/plain")
		sgAtt.SetFilename(a.Name)
		sgAtt.SetDisposition("attachment")
		sgAttachments = append(sgAttachments, sgAtt)
	}
	m.AddAttachment(sgAttachments...)

	// Build and send the request.
	request := sendgrid.GetRequest(s.apiKey, "/v3/mail/send", "https://api.sendgrid.com")
	request.Method = "POST"
	request.Body = mail.GetRequestBody(m)
	_, err := sendgrid.API(request)
	return err
}
