package user_models

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/go-bolo/bolo"
	"github.com/go-bolo/bolo/helpers"
	"github.com/go-bolo/clock"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type UserModel struct {
	ID uint64 `gorm:"primary_key;column:id;" json:"id" filter:"param:id;type:number"`

	Username string `gorm:"unique;column:username;" json:"username" filter:"param:username;type:string"`
	Email    string `gorm:"unique;column:email;" json:"email" filter:"param:email;type:string"`

	DisplayName string `gorm:"column:displayName;" json:"displayName" filter:"param:displayName;type:string"`
	FullName    string `gorm:"column:fullName;" json:"fullName" filter:"param:fullName;type:string"`
	Biography   string `gorm:"column:biography;type:TEXT;" json:"biography" filter:"param:biography;type:string"`
	Gender      string `gorm:"column:gender;" json:"gender" filter:"param:gender;type:string"`

	Active  bool `gorm:"column:active;" json:"active"`
	Blocked bool `gorm:"column:blocked;" json:"blocked" filter:"param:blocked;type:bool"`

	Language     string `gorm:"column:language;" json:"language" filter:"param:language;type:string"`
	ConfirmEmail string `gorm:"column:confirmEmail;" json:"confirmEmail"`

	AcceptTerms bool   `gorm:"column:acceptTerms;" json:"acceptTerms"`
	Birthdate   string `gorm:"column:birthdate;" json:"birthdate" filter:"param:birthdate;type:date"`
	Phone       string `gorm:"column:phone;" json:"phone" filter:"param:phone;type:string"`

	Roles     []string `gorm:"-" json:"roles"`
	RolesText string   `gorm:"column:roles;" json:"-"`

	CreatedAt time.Time `gorm:"column:createdAt;autoCreateTime:false;" json:"createdAt" filter:"param:createdAt;type:date"`
	UpdatedAt time.Time `gorm:"column:updatedAt;autoupdatetime:false;default:null;" json:"updatedAt" filter:"param:updatedAt;type:date"`
}

func (r *UserModel) GetID() string {
	return strconv.FormatUint(r.ID, 10)
}

func (r *UserModel) SetID(id string) error {
	n, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return err
	}
	r.ID = n

	return nil
}

func (r *UserModel) SetRoles(v []string) error {
	r.Roles = v

	jsonString, _ := json.Marshal(r.Roles)
	r.RolesText = string(jsonString)

	return nil
}

func (r *UserModel) AddRole(role string) error {
	for i := range r.Roles {
		if r.Roles[i] == role {
			return nil
		}
	}

	r.Roles = append(r.Roles, role)

	return nil
}

func (r *UserModel) RemoveRole(role string) error {
	// r.Roles.
	r.Roles, _ = helpers.SliceRemove(r.Roles, role)
	return nil
}

func (r *UserModel) GetEmail() string {
	return r.Email
}

func (r *UserModel) SetEmail(v string) error {
	// TODO! Validate email format!
	r.Email = v
	return nil
}

func (r *UserModel) GetUsername() string {
	return r.Username
}

func (r *UserModel) SetUsername(v string) error {
	r.Username = v
	return nil
}

func (r *UserModel) SetDisplayName(v string) error {
	r.DisplayName = v
	return nil
}

func (r *UserModel) SetFullName(v string) error {
	r.FullName = v
	return nil
}

func (r *UserModel) GetLanguage() string {
	return r.Language
}

func (r *UserModel) SetLanguage(v string) error {
	// TODO! Validate if this land is valid
	r.Language = v
	return nil
}

func (r *UserModel) IsActive() bool {
	return r.Active
}

func (r *UserModel) SetActive(v bool) error {
	r.Active = v
	return nil
}

func (r *UserModel) SetBlocked(blocked bool) error {
	r.Blocked = blocked
	return nil
}

func (UserModel) TableName() string {
	return "users"
}

func (r *UserModel) FillById(id string) error {
	return UserFindOne(id, r)
}

func (r *UserModel) GetRoles() []string {
	if r.RolesText != "" {
		_ = json.Unmarshal([]byte(r.RolesText), &r.Roles)
	}

	return r.Roles
}

func (r *UserModel) SetRole(roleName string) []string {
	roles := r.GetRoles()
	roles = append(roles, roleName)

	jsonString, _ := json.Marshal(roles)
	r.RolesText = string(jsonString)

	r.Roles = roles

	return r.Roles
}

func (r *UserModel) GetDisplayName() string {
	return r.DisplayName
}

func (r *UserModel) GetFullName() string {
	return r.FullName
}

func (r *UserModel) IsBlocked() bool {
	return r.Blocked
}

func (r *UserModel) GetBiography() string {
	return r.Biography
}

func (r *UserModel) GetGender() string {
	return r.Gender
}

func (r *UserModel) GetActiveString() string {
	return strconv.FormatBool(r.Active)
}

func (r *UserModel) GetBlockedString() string {
	return strconv.FormatBool(r.Blocked)
}

func (r *UserModel) GetAcceptTermsString() string {
	return strconv.FormatBool(r.AcceptTerms)
}

func (r *UserModel) GetBirthdate() string {
	return r.Birthdate
}

func (r *UserModel) GetPhone() string {
	return r.Phone
}

func (r *UserModel) GetCreatedAtString() string {
	return r.CreatedAt.UTC().String()
}

func (r *UserModel) GetUpdateAtString() string {
	return r.UpdatedAt.UTC().String()
}

func (m *UserModel) Save(ctx *bolo.RequestContext) error {
	var err error
	db := ctx.App.GetDB()
	app := ctx.App
	m.UpdatedAt = app.GetClock().Now()

	if m.ID == 0 {
		m.CreatedAt = clock.New().Now()
		// create ....
		err = db.Create(&m).Error
		if err != nil {
			return err
		}
	} else {
		// update ...
		err = db.Save(&m).Error
		if err != nil {
			return err
		}
	}

	// TODO! re-set url alias

	return nil
}

func (m *UserModel) LoadTeaserData() error {
	m.GetRoles()
	return nil
}

func (m *UserModel) LoadData() error {
	m.GetRoles()
	return nil
}

func (r *UserModel) Delete() error {
	if r.ID == 0 {
		return nil
	}
	db := bolo.GetDefaultDatabaseConnection()
	return db.Unscoped().Delete(&r).Error
}

func (m *UserModel) ValidPassword(password string) (bool, error) {
	var passwordRecord PasswordModel

	err := FindPasswordByUserID(m.GetID(), &passwordRecord)
	if err != nil {
		return false, err
	}

	isValid, err := passwordRecord.Compare(password)
	if err != nil && !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, err
	}

	if !isValid {
		return false, nil
	}

	return true, nil
}

func (m *UserModel) SetPassword(password string) error {
	return UpdateUserPasswordByUserID(m.GetID(), password)
}

func UsersQuery(userList *[]UserModel, limit int) error {

	db := bolo.GetDefaultDatabaseConnection()

	if err := db.
		Limit(limit).
		Find(userList).Error; err != nil {
		return err
	}
	return nil
}

// FindOne - Find one user record
func UserFindOne(id string, record *UserModel) error {
	db := bolo.GetDefaultDatabaseConnection()

	idInt, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return err
	}

	err = db.
		Where("id = ?", idInt).
		First(record).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return nil
}

func UserFindOneByUsername(username string, record *UserModel) error {
	db := bolo.GetDefaultDatabaseConnection()

	return db.
		Where(
			db.Where("username = ?", username).
				Or(db.Where("email = ?", username)),
		).
		First(record).Error
}

func LoadAllUsers(userList *[]UserModel) error {
	db := bolo.GetDefaultDatabaseConnection()

	if err := db.
		Limit(99999).
		Order("displayName ASC, id ASC").
		Find(userList).Error; err != nil {
		return err
	}
	return nil

}

type QueryAndCountFromRequestCfg struct {
	Records *[]*UserModel
	Count   *int64
	Limit   int
	Offset  int
	C       echo.Context
	IsHTML  bool
}

func QueryAndCountFromRequest(opts *QueryAndCountFromRequestCfg) error {
	db := bolo.GetDefaultDatabaseConnection()

	c := opts.C

	q := c.QueryParam("q")
	query := db
	ctx := c.(*bolo.RequestContext)

	can := ctx.Can("find_user")
	if !can {
		logrus.WithFields(logrus.Fields{
			"roles": ctx.GetAuthenticatedRoles(),
		}).Debug("QueryAndCountFromRequest forbidden")

		return nil
	}

	queryI, err := ctx.Query.SetDatabaseQueryForModel(query, &UserModel{})
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": fmt.Sprintf("%+v\n", err),
		}).Error("QueryAndCountFromRequest error")
	}
	query = queryI.(*gorm.DB)

	if q != "" {
		query = query.Where(
			db.Where("displayName LIKE ?", "%"+q+"%").Or(db.Where("fullName LIKE ?", "%"+q+"%")),
		)
	}

	orderColumn, orderIsDesc, orderValid := helpers.ParseUrlQueryOrder(c.QueryParam("order"), c.QueryParam("sort"), c.QueryParam("sortDirection"))

	if orderValid {
		query = query.Order(clause.OrderByColumn{
			Column: clause.Column{Table: clause.CurrentTable, Name: orderColumn},
			Desc:   orderIsDesc,
		})
	} else {
		query = query.Order("createdAt DESC").
			Order("id DESC")
	}

	query = query.Limit(opts.Limit).
		Offset(opts.Offset)

	r := query.Find(opts.Records)
	if r.Error != nil {
		return errors.Wrap(r.Error, "user.QueryAndCountFromRequest error on find records")
	}

	return CountQueryFromRequest(opts)
}

func CountQueryFromRequest(opts *QueryAndCountFromRequestCfg) error {
	db := bolo.GetDefaultDatabaseConnection()

	c := opts.C
	q := c.QueryParam("q")
	ctx := c.(*bolo.RequestContext)

	// Count ...
	queryCount := db

	if q != "" {
		queryCount = queryCount.Or(
			db.Where("displayName LIKE ?", "%"+q+"%"),
			db.Where("fullName LIKE ?", "%"+q+"%"),
		)
	}

	can := ctx.Can("find_user")
	if !can {
		return nil
	}

	queryICount, err := ctx.Query.SetDatabaseQueryForModel(queryCount, &UserModel{})
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": fmt.Sprintf("%+v\n", err),
		}).Error("QueryAndCountFromRequest count error")
	}
	queryCount = queryICount.(*gorm.DB)

	return queryCount.
		Table("users").
		Count(opts.Count).Error
}
