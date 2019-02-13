package cache

import (
	"bytes"
	"encoding/binary"
	"sync"
	"time"

	"github.com/go-redis/redis"
	"github.com/google/uuid"
	"github.com/renproject/auther/foundation"
)

type Cache struct {
	*redis.Client

	inMemTokensMu        *sync.RWMutex
	inMemTokens          map[uuid.UUID]foundation.Token
	inMemTokenTimestamps map[uuid.UUID]time.Time
}

func New(client *redis.Client) *Cache {
	return &Cache{
		Client: client,

		inMemTokensMu:        new(sync.RWMutex),
		inMemTokens:          map[uuid.UUID]foundation.Token{},
		inMemTokenTimestamps: map[uuid.UUID]time.Time{},
	}
}

func (cache *Cache) InsertToken(token *foundation.Token) error {
	cache.inMemTokensMu.Lock()
	cache.inMemTokens[token.UUID] = *token
	cache.inMemTokenTimestamps[token.UUID] = time.Now()
	cache.inMemTokensMu.Unlock()

	data, err := MarshalToken(token)
	if err != nil {
		return err
	}
	return cache.Client.Set(token.UUID.String(), data, 24*7*time.Hour).Err()
}

func (cache *Cache) DeleteToken(uuid uuid.UUID) error {
	cache.inMemTokensMu.Lock()
	delete(cache.inMemTokens, uuid)
	delete(cache.inMemTokenTimestamps, uuid)
	cache.inMemTokensMu.Unlock()

	return cache.Client.Del(uuid.String()).Err()
}

func (cache *Cache) Token(uuid uuid.UUID) (foundation.Token, error) {

	cache.inMemTokensMu.RLock()
	token, tokenOk := cache.inMemTokens[uuid]
	tokenTimestamp, tokenTimestampOk := cache.inMemTokenTimestamps[uuid]
	cache.inMemTokensMu.RUnlock()

	if tokenOk && tokenTimestampOk {
		if tokenTimestamp.Add(time.Hour).After(time.Now()) {
			return token, nil
		}
		cache.inMemTokensMu.Lock()
		delete(cache.inMemTokens, uuid)
		delete(cache.inMemTokenTimestamps, uuid)
		cache.inMemTokensMu.Unlock()
	}

	value, err := cache.Client.Get(uuid.String()).Result()
	if err != nil {
		return foundation.Token{}, err
	}

	token, err = UnmarshalToken([]byte(value))
	if err != nil {
		return foundation.Token{}, err
	}

	cache.inMemTokensMu.Lock()
	cache.inMemTokens[uuid] = token
	cache.inMemTokenTimestamps[uuid] = time.Now()
	cache.inMemTokensMu.Unlock()

	return token, nil
}

func MarshalToken(token *foundation.Token) ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, token.ID); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, token.UUID); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, token.CreatedAt.Unix()); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, token.ExpiredAt.Unix()); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, int64(len(token.Access))); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, []byte(token.Access)); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, int64(len(token.JWT))); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, []byte(token.JWT)); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, token.UserID); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func UnmarshalToken(data []byte) (foundation.Token, error) {
	buf := bytes.NewReader(data)

	token := foundation.Token{}

	if err := binary.Read(buf, binary.BigEndian, &token.ID); err != nil {
		return foundation.Token{}, err
	}
	if err := binary.Read(buf, binary.BigEndian, &token.UUID); err != nil {
		return foundation.Token{}, err
	}

	createdAt := int64(0)
	if err := binary.Read(buf, binary.BigEndian, &createdAt); err != nil {
		return foundation.Token{}, err
	}

	expiredAt := int64(0)
	if err := binary.Read(buf, binary.BigEndian, &expiredAt); err != nil {
		return foundation.Token{}, err
	}

	accessLen := int64(0)
	if err := binary.Read(buf, binary.BigEndian, &accessLen); err != nil {
		return foundation.Token{}, err
	}
	access := make([]byte, accessLen)
	if err := binary.Read(buf, binary.BigEndian, access); err != nil {
		return foundation.Token{}, err
	}

	jwtLen := int64(0)
	if err := binary.Read(buf, binary.BigEndian, &jwtLen); err != nil {
		return foundation.Token{}, err
	}
	jwt := make([]byte, jwtLen)
	if err := binary.Read(buf, binary.BigEndian, jwt); err != nil {
		return foundation.Token{}, err
	}

	if err := binary.Read(buf, binary.BigEndian, &token.UserID); err != nil {
		return foundation.Token{}, err
	}

	token.CreatedAt = time.Unix(createdAt, 0)
	token.ExpiredAt = time.Unix(expiredAt, 0)
	token.Access = foundation.Access(access)
	token.JWT = string(jwt)

	return token, nil
}
