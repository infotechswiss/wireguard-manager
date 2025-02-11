package emailer

// Attachment represents a file attachment to be sent with an email.
type Attachment struct {
	// Name is the filename of the attachment.
	Name string
	// Data holds the binary content of the attachment.
	Data []byte
}

// Emailer defines an interface for sending emails.
// Implementations should handle constructing and sending emails
// with optional attachments.
type Emailer interface {
	// Send sends an email with the provided details.
	//
	// Parameters:
	//   toName:    The recipient's name.
	//   to:        The recipient's email address.
	//   subject:   The email subject.
	//   content:   The email body content (can include HTML).
	//   attachments: A slice of Attachment objects to include with the email.
	//
	// Returns an error if sending fails.
	Send(toName string, to string, subject string, content string, attachments []Attachment) error
}
