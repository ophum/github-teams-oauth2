package schema

import "entgo.io/ent"

// AccessToken holds the schema definition for the AccessToken entity.
type AccessToken struct {
	ent.Schema
}

// Fields of the AccessToken.
func (AccessToken) Fields() []ent.Field {
	return nil
}

// Edges of the AccessToken.
func (AccessToken) Edges() []ent.Edge {
	return nil
}
