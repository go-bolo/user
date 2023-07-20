package user

import (
	"strconv"

	"github.com/go-bolo/bolo"
	"github.com/pkg/errors"
	"gorm.io/gorm"

	"time"

	"golang.org/x/crypto/bcrypt"
)

type PasswordModel struct {
	ID        uint64    `gorm:"primary_key;column:id;" json:"id"`
	UserID    *int64    `gorm:"column:userId;type:bigint(20)" json:"userId"`
	Password  string    `gorm:"column:password;type:text" json:"password"`
	CreatedAt time.Time `gorm:"column:createdAt;type:datetime;not null" json:"createdAt"`
	UpdatedAt time.Time `gorm:"column:updatedAt;type:datetime;not null" json:"updatedAt"`
}

func (r *PasswordModel) TableName() string {
	return "passwords"
}

// Generate hash from password and set if in .Password attr
// @param password string raw password to be hashed
func (r *PasswordModel) SetPassword(password string) error {
	if password == "" {
		return errors.New("password should not be empty")
	}

	hashedPassword, err := r.Generate(password)
	if err != nil {
		return err
	}

	r.Password = string(hashedPassword)

	return nil
}
func (r *PasswordModel) Compare(password string) (bool, error) {
	if r.Password == "" {
		// 404 or empty
		return false, errors.New("password should not be empty")
	}

	hashedPassword := []byte(r.Password)

	err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		return false, errors.Wrap(err, "Error on bcrypt.CompareHashAndPassword")
	}

	return true, nil
}

func (r *PasswordModel) Generate(password string) ([]byte, error) {
	if password == "" {
		// 404 or empty
		return nil, errors.New("password should not be empty")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.Wrap(err, "Error on bcrypt.GenerateFromPassword")
	}

	return hashedPassword, nil
}

func (r *PasswordModel) Save(app bolo.App) error {
	var err error

	db := app.GetDB()

	if r.ID == 0 {
		// create ....
		err = db.Create(&r).Error
		if err != nil {
			return err
		}
	} else {
		// update ...
		err = db.Save(&r).Error
		if err != nil {
			return err
		}
	}

	return nil
}

func FindPasswordByUsername(app bolo.App, username string, r *PasswordModel) error {
	db := app.GetDB()

	err := db.
		Model(&PasswordModel{}).
		Select("passwords.id, passwords.userId, passwords.password").
		Joins("LEFT JOIN users on users.id = passwords.userId").
		Where(
			db.Where("users.username = ?", username).
				Or(db.Where("users.email = ?", username)),
		).
		First(r).Error

	if err != nil {
		return err
	}

	return nil
}

func FindPasswordByUserID(app bolo.App, userID string, passwordRecord *PasswordModel) error {
	db := app.GetDB()
	err := db.Where("userId", userID).
		First(&passwordRecord).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return nil
}

func UpdateUserPasswordByUserID(app bolo.App, userID string, password string) error {
	var record PasswordModel
	err := FindPasswordByUserID(app, userID, &record)
	if err != nil {
		return err
	}

	if record.ID == 0 {
		v, err := strconv.ParseInt(userID, 10, 64)
		if err != nil {
			return err
		}

		record.UserID = &v
	}

	err = record.SetPassword(password)
	if err != nil {
		return err
	}

	return record.Save(app)
}
