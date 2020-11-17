package server

import (
	"encoding/json"
	"fmt"
	"net/url"
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

// SecretNameToID returns the ID of the named secret, if only a single exact match is found. If no exact match is found
// an error is returned. If multiple exact matches are found an error of type MultipleSecretsFoundError is returned
// containing the IDs for all matched secrets.
func (s Server) SecretNameToID(name string) (int, error) {
	filter := url.Values{
		"filter.searchFieldSlug":     {"name"},
		"filter.searchText":          {name},
		"filter.doNotCalculateTotal": {"true"},
	}.Encode()

	if data, err := s.accessResource("GET", resource, "?"+filter, nil); err == nil {
		// Declare structs in the local scope for unmarshaling
		type record struct {
			ID                 int
			Name               string
			SecretTemplateID   int
			SecretTemplateName string
		}

		u := struct {
			Records []record
		}{}

		// Unmarshal response
		if err = json.Unmarshal(data, &u); err != nil {
			return 0, fmt.Errorf("unmarshaling response: %s", err)
		}

		// Handle multiple returned values
		switch {
		case len(u.Records) > 1:
			ids := make([]int, len(u.Records))
			for i, r := range u.Records {
				ids[i] = r.ID
			}

			return 0, MultipleSecretsFoundError{IDs: ids, searchedName: name}
		case len(u.Records) < 1:
			return 0, fmt.Errorf("no secrets found with name '%s'", name)
		default:
			return u.Records[0].ID, nil
		}
	} else {
		return 0, fmt.Errorf("accessing resource %s: %s", resource, err)
	}
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

// MultipleSecretsFoundError reports an error where multiple exact matches were found for a secret name search.
type MultipleSecretsFoundError struct {
	IDs          []int  // Secret IDs for all matched secrets
	searchedName string // Name which matched the secrets
}

func (e MultipleSecretsFoundError) Error() string {
	return fmt.Sprintf("multiple (%d) secrets found with name %s", len(e.IDs), e.searchedName)
}
