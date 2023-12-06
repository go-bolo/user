package user_models

import (
	"time"

	"github.com/go-bolo/bolo"
	"github.com/go-bolo/bolo/helpers"
)

type AuthTokenModel struct {
	ID              uint64  `gorm:"primary_key;column:id;" json:"id" filter:"param:id;type:number"`
	UserID          *string `gorm:"index:userId;column:userId;type:int(11)" json:"userId" filter:"param:userId;type:number"`
	ProviderUserID  int64   `gorm:"column:providerUserId;type:BIGINT" json:"providerUserId" filter:"param:providerUserId;type:string"`
	TokenProviderID string  `gorm:"column:tokenProviderId;type:VARCHAR(255)" json:"tokenProviderId" filter:"param:tokenProviderId;type:string"`

	TokenType   string `gorm:"column:tokenType;type:VARCHAR(255)" json:"tokenType" filter:"param:tokenType;type:string"`
	Token       string `gorm:"column:token;type:VARCHAR(255)" json:"token" filter:"param:token;type:string"`
	IsValid     bool   `gorm:"column:isValid" json:"isValid" filter:"param:isValid;type:bool"`
	RedirectURL string `gorm:"column:redirectUrl;type:TEXT" json:"redirectUrl" filter:"param:redirectUrl;type:string"`

	CreatedAt time.Time `gorm:"column:createdAt;" json:"createdAt" filter:"param:createdAt"`
	UpdatedAt time.Time `gorm:"column:updatedAt;" json:"updatedAt" filter:"param:updatedAt"`
}

func (r *AuthTokenModel) TableName() string {
	return "authtokens"
}

func (r *AuthTokenModel) Delete() error {
	db := bolo.GetDefaultDatabaseConnection()
	return db.Unscoped().Delete(&r).Error
}

func (r *AuthTokenModel) Save() error {
	db := bolo.GetDefaultDatabaseConnection()

	if r.ID == 0 {
		if r.Token == "" {
			r.Token = helpers.RandStringBytes(35)
		}

		// create ....
		err := db.Create(&r).Error
		if err != nil {
			return err
		}
	} else {
		// update ...
		err := db.Save(&r).Error
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *AuthTokenModel) GetResetUrl(ctx *bolo.RequestContext, resetPrefixName string, resetPrefixNames map[string]string) string {
	if resetPrefixName != "" {
		if v, found := resetPrefixNames[resetPrefixName]; found {
			return v + "t=" + r.Token + "&u=" + *r.UserID
		}
	}

	baseUrl := ctx.AppOrigin
	return baseUrl + "/auth/" + *r.UserID + "/forgot-password/reset?t=" + r.Token
}

func FindInvalidOldUserTokens(uid string) ([]*AuthTokenModel, error) {
	var tokens []*AuthTokenModel

	db := bolo.GetDefaultDatabaseConnection()

	err := db.Model(&AuthTokenModel{}).
		Where("userId = ? AND isValid = ?", uid, false).
		Find(&tokens).
		Error

	return tokens, err
}

func ValidAuthToken(userID string, token string) (bool, *AuthTokenModel, error) {
	var authToken AuthTokenModel

	db := bolo.GetDefaultDatabaseConnection()

	err := db.Model(&AuthTokenModel{}).
		Where("token = ? AND userId = ?", token, userID).
		First(&authToken).
		Error

	if err != nil {
		return false, nil, err
	}

	if !authToken.IsValid {
		return false, nil, nil
	}

	return true, &authToken, nil
}

func FindOneAuthToken(id string) (*AuthTokenModel, error) {
	db := bolo.GetDefaultDatabaseConnection()

	var token AuthTokenModel

	err := db.Model(&AuthTokenModel{}).
		Where("id = ?", id).
		First(&token).
		Error

	return &token, err
}

func CreateAuthToken(userID, tokenType string) (*AuthTokenModel, error) {
	t := AuthTokenModel{
		UserID:    &userID,
		TokenType: tokenType,
		IsValid:   true,
	}

	err := t.Save()
	return &t, err
}
