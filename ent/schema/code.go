package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// Code holds the schema definition for the Code entity.
type Code struct {
	ent.Schema
}

// Fields of the Code.
func (Code) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New),
		field.String("code"),
	}
}

// Edges of the Code.
func (Code) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).Ref("codes").Unique(),
		edge.From("group", Group.Type).Ref("codes").Unique(),
	}
}
