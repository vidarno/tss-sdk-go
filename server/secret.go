package server

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// resource is the HTTP URL path component for the secrets resource
const resource = "secrets"

// Secret represents a secret from Thycotic Secret Server
type Secret struct {
	Name                                string
	FolderID, ID, SiteID                int
	SecretTemplateID, SecretPolicyID    int
	Active, CheckedOut, CheckOutEnabled bool
	Fields                              []SecretField `json:"Items"`
}

// SecretField is an item (field) in the secret
type SecretField struct {
	ItemID, FieldID, FileAttachmentID                      int
	FieldDescription, FieldName, Filename, ItemValue, Slug string
	IsFile, IsNotes, IsPassword                            bool
}

// Secret gets the secret with id from the Secret Server of the given tenant
func (s Server) Secret(id int) (*Secret, error) {
	secret := new(Secret)

	if data, err := s.accessResource("GET", resource, strconv.Itoa(id), nil); err == nil {
		if err = json.Unmarshal(data, secret); err != nil {
			return nil, fmt.Errorf("parsing response from /%s/%d: %s", resource, id, err)
		}
	} else {
		return nil, err
	}

	// automatically download file attachments and substitute them for the
	// (dummy) ItemValue, so as to make the process transparent to the caller
	for index, element := range secret.Fields {
		if element.FileAttachmentID != 0 {
			path := fmt.Sprintf("%d/fields/%s", id, element.Slug)

			if data, err := s.accessResource("GET", resource, path, nil); err == nil {
				secret.Fields[index].ItemValue = string(data)
			} else {
				return nil, err
			}
		}
	}

	return secret, nil
}

// Field returns the value of the field with the name fieldName
func (s Secret) Field(fieldName string) (string, bool) {
	for _, field := range s.Fields {
		if fieldName == field.FieldName || fieldName == field.Slug {
			return field.ItemValue, true
		}
	}

	return "", false
}
