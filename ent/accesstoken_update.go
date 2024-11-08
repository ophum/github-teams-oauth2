// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/ophum/github-teams-oauth2/ent/accesstoken"
	"github.com/ophum/github-teams-oauth2/ent/group"
	"github.com/ophum/github-teams-oauth2/ent/predicate"
	"github.com/ophum/github-teams-oauth2/ent/user"
)

// AccessTokenUpdate is the builder for updating AccessToken entities.
type AccessTokenUpdate struct {
	config
	hooks    []Hook
	mutation *AccessTokenMutation
}

// Where appends a list predicates to the AccessTokenUpdate builder.
func (atu *AccessTokenUpdate) Where(ps ...predicate.AccessToken) *AccessTokenUpdate {
	atu.mutation.Where(ps...)
	return atu
}

// SetToken sets the "token" field.
func (atu *AccessTokenUpdate) SetToken(s string) *AccessTokenUpdate {
	atu.mutation.SetToken(s)
	return atu
}

// SetNillableToken sets the "token" field if the given value is not nil.
func (atu *AccessTokenUpdate) SetNillableToken(s *string) *AccessTokenUpdate {
	if s != nil {
		atu.SetToken(*s)
	}
	return atu
}

// SetExpiresAt sets the "expires_at" field.
func (atu *AccessTokenUpdate) SetExpiresAt(t time.Time) *AccessTokenUpdate {
	atu.mutation.SetExpiresAt(t)
	return atu
}

// SetNillableExpiresAt sets the "expires_at" field if the given value is not nil.
func (atu *AccessTokenUpdate) SetNillableExpiresAt(t *time.Time) *AccessTokenUpdate {
	if t != nil {
		atu.SetExpiresAt(*t)
	}
	return atu
}

// SetUserID sets the "user" edge to the User entity by ID.
func (atu *AccessTokenUpdate) SetUserID(id uuid.UUID) *AccessTokenUpdate {
	atu.mutation.SetUserID(id)
	return atu
}

// SetNillableUserID sets the "user" edge to the User entity by ID if the given value is not nil.
func (atu *AccessTokenUpdate) SetNillableUserID(id *uuid.UUID) *AccessTokenUpdate {
	if id != nil {
		atu = atu.SetUserID(*id)
	}
	return atu
}

// SetUser sets the "user" edge to the User entity.
func (atu *AccessTokenUpdate) SetUser(u *User) *AccessTokenUpdate {
	return atu.SetUserID(u.ID)
}

// SetGroupID sets the "group" edge to the Group entity by ID.
func (atu *AccessTokenUpdate) SetGroupID(id uuid.UUID) *AccessTokenUpdate {
	atu.mutation.SetGroupID(id)
	return atu
}

// SetNillableGroupID sets the "group" edge to the Group entity by ID if the given value is not nil.
func (atu *AccessTokenUpdate) SetNillableGroupID(id *uuid.UUID) *AccessTokenUpdate {
	if id != nil {
		atu = atu.SetGroupID(*id)
	}
	return atu
}

// SetGroup sets the "group" edge to the Group entity.
func (atu *AccessTokenUpdate) SetGroup(g *Group) *AccessTokenUpdate {
	return atu.SetGroupID(g.ID)
}

// Mutation returns the AccessTokenMutation object of the builder.
func (atu *AccessTokenUpdate) Mutation() *AccessTokenMutation {
	return atu.mutation
}

// ClearUser clears the "user" edge to the User entity.
func (atu *AccessTokenUpdate) ClearUser() *AccessTokenUpdate {
	atu.mutation.ClearUser()
	return atu
}

// ClearGroup clears the "group" edge to the Group entity.
func (atu *AccessTokenUpdate) ClearGroup() *AccessTokenUpdate {
	atu.mutation.ClearGroup()
	return atu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (atu *AccessTokenUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, atu.sqlSave, atu.mutation, atu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (atu *AccessTokenUpdate) SaveX(ctx context.Context) int {
	affected, err := atu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (atu *AccessTokenUpdate) Exec(ctx context.Context) error {
	_, err := atu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (atu *AccessTokenUpdate) ExecX(ctx context.Context) {
	if err := atu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (atu *AccessTokenUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(accesstoken.Table, accesstoken.Columns, sqlgraph.NewFieldSpec(accesstoken.FieldID, field.TypeUUID))
	if ps := atu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := atu.mutation.Token(); ok {
		_spec.SetField(accesstoken.FieldToken, field.TypeString, value)
	}
	if value, ok := atu.mutation.ExpiresAt(); ok {
		_spec.SetField(accesstoken.FieldExpiresAt, field.TypeTime, value)
	}
	if atu.mutation.UserCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   accesstoken.UserTable,
			Columns: []string{accesstoken.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := atu.mutation.UserIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   accesstoken.UserTable,
			Columns: []string{accesstoken.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if atu.mutation.GroupCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   accesstoken.GroupTable,
			Columns: []string{accesstoken.GroupColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(group.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := atu.mutation.GroupIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   accesstoken.GroupTable,
			Columns: []string{accesstoken.GroupColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(group.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, atu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{accesstoken.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	atu.mutation.done = true
	return n, nil
}

// AccessTokenUpdateOne is the builder for updating a single AccessToken entity.
type AccessTokenUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *AccessTokenMutation
}

// SetToken sets the "token" field.
func (atuo *AccessTokenUpdateOne) SetToken(s string) *AccessTokenUpdateOne {
	atuo.mutation.SetToken(s)
	return atuo
}

// SetNillableToken sets the "token" field if the given value is not nil.
func (atuo *AccessTokenUpdateOne) SetNillableToken(s *string) *AccessTokenUpdateOne {
	if s != nil {
		atuo.SetToken(*s)
	}
	return atuo
}

// SetExpiresAt sets the "expires_at" field.
func (atuo *AccessTokenUpdateOne) SetExpiresAt(t time.Time) *AccessTokenUpdateOne {
	atuo.mutation.SetExpiresAt(t)
	return atuo
}

// SetNillableExpiresAt sets the "expires_at" field if the given value is not nil.
func (atuo *AccessTokenUpdateOne) SetNillableExpiresAt(t *time.Time) *AccessTokenUpdateOne {
	if t != nil {
		atuo.SetExpiresAt(*t)
	}
	return atuo
}

// SetUserID sets the "user" edge to the User entity by ID.
func (atuo *AccessTokenUpdateOne) SetUserID(id uuid.UUID) *AccessTokenUpdateOne {
	atuo.mutation.SetUserID(id)
	return atuo
}

// SetNillableUserID sets the "user" edge to the User entity by ID if the given value is not nil.
func (atuo *AccessTokenUpdateOne) SetNillableUserID(id *uuid.UUID) *AccessTokenUpdateOne {
	if id != nil {
		atuo = atuo.SetUserID(*id)
	}
	return atuo
}

// SetUser sets the "user" edge to the User entity.
func (atuo *AccessTokenUpdateOne) SetUser(u *User) *AccessTokenUpdateOne {
	return atuo.SetUserID(u.ID)
}

// SetGroupID sets the "group" edge to the Group entity by ID.
func (atuo *AccessTokenUpdateOne) SetGroupID(id uuid.UUID) *AccessTokenUpdateOne {
	atuo.mutation.SetGroupID(id)
	return atuo
}

// SetNillableGroupID sets the "group" edge to the Group entity by ID if the given value is not nil.
func (atuo *AccessTokenUpdateOne) SetNillableGroupID(id *uuid.UUID) *AccessTokenUpdateOne {
	if id != nil {
		atuo = atuo.SetGroupID(*id)
	}
	return atuo
}

// SetGroup sets the "group" edge to the Group entity.
func (atuo *AccessTokenUpdateOne) SetGroup(g *Group) *AccessTokenUpdateOne {
	return atuo.SetGroupID(g.ID)
}

// Mutation returns the AccessTokenMutation object of the builder.
func (atuo *AccessTokenUpdateOne) Mutation() *AccessTokenMutation {
	return atuo.mutation
}

// ClearUser clears the "user" edge to the User entity.
func (atuo *AccessTokenUpdateOne) ClearUser() *AccessTokenUpdateOne {
	atuo.mutation.ClearUser()
	return atuo
}

// ClearGroup clears the "group" edge to the Group entity.
func (atuo *AccessTokenUpdateOne) ClearGroup() *AccessTokenUpdateOne {
	atuo.mutation.ClearGroup()
	return atuo
}

// Where appends a list predicates to the AccessTokenUpdate builder.
func (atuo *AccessTokenUpdateOne) Where(ps ...predicate.AccessToken) *AccessTokenUpdateOne {
	atuo.mutation.Where(ps...)
	return atuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (atuo *AccessTokenUpdateOne) Select(field string, fields ...string) *AccessTokenUpdateOne {
	atuo.fields = append([]string{field}, fields...)
	return atuo
}

// Save executes the query and returns the updated AccessToken entity.
func (atuo *AccessTokenUpdateOne) Save(ctx context.Context) (*AccessToken, error) {
	return withHooks(ctx, atuo.sqlSave, atuo.mutation, atuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (atuo *AccessTokenUpdateOne) SaveX(ctx context.Context) *AccessToken {
	node, err := atuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (atuo *AccessTokenUpdateOne) Exec(ctx context.Context) error {
	_, err := atuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (atuo *AccessTokenUpdateOne) ExecX(ctx context.Context) {
	if err := atuo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (atuo *AccessTokenUpdateOne) sqlSave(ctx context.Context) (_node *AccessToken, err error) {
	_spec := sqlgraph.NewUpdateSpec(accesstoken.Table, accesstoken.Columns, sqlgraph.NewFieldSpec(accesstoken.FieldID, field.TypeUUID))
	id, ok := atuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "AccessToken.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := atuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, accesstoken.FieldID)
		for _, f := range fields {
			if !accesstoken.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != accesstoken.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := atuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := atuo.mutation.Token(); ok {
		_spec.SetField(accesstoken.FieldToken, field.TypeString, value)
	}
	if value, ok := atuo.mutation.ExpiresAt(); ok {
		_spec.SetField(accesstoken.FieldExpiresAt, field.TypeTime, value)
	}
	if atuo.mutation.UserCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   accesstoken.UserTable,
			Columns: []string{accesstoken.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := atuo.mutation.UserIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   accesstoken.UserTable,
			Columns: []string{accesstoken.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if atuo.mutation.GroupCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   accesstoken.GroupTable,
			Columns: []string{accesstoken.GroupColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(group.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := atuo.mutation.GroupIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   accesstoken.GroupTable,
			Columns: []string{accesstoken.GroupColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(group.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &AccessToken{config: atuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, atuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{accesstoken.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	atuo.mutation.done = true
	return _node, nil
}
