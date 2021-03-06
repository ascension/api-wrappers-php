<?php

/**
 * @file
 * Tests JSON deserialisation of miiCard API artefacts into PHP objects.
 */

use miiCard\Consumers\Model;

require_once '../miiCard.Model.php';

class IdentitySnapshotDetailsTest extends PHPUnit_Framework_TestCase {
  protected $jsonBody = '{"SnapshotId":"0fc60a0e-a058-4cae-bae1-460db73f2947","TimestampUtc":"\/Date(1351594328296)\/","Username":"testuser","WasTestUser":true}';

  /**
   * Ensures identity snapshot metadata can be deserialised.
   */
  public function testCanDeserialiseIdentitySnapshotDetailsResponse() {
    $o = Model\IdentitySnapshotDetails::FromHash(json_decode($this->jsonBody, TRUE));

    $this->assertEquals("0fc60a0e-a058-4cae-bae1-460db73f2947", $o->getSnapshotId());
    $this->assertEquals(1351594328.296, $o->getTimestampUtc());
    $this->assertEquals("testuser", $o->getUsername());
    $this->assertTrue($o->getWasTestUser());
  }
}

class MiiUserProfileTest extends PHPUnit_Framework_TestCase {
  protected $jsonBody = '{"CardImageUrl":"https:\/\/my.miicard.com\/img\/test.png","DateOfBirth":"\/Date(445046400000)\/","EmailAddresses":[{"Verified":true,"Address":"test@example.com","DisplayName":"testEmail","IsPrimary":true},{"Verified":false,"Address":"test2@example.com","DisplayName":"test2Email","IsPrimary":false}],"FirstName":"Test","HasPublicProfile":true,"Identities":null,"IdentityAssured":true,"LastName":"User","LastVerified":"\/Date(1345812103000)\/","MiddleName":"Middle","PhoneNumbers":[{"Verified":true,"CountryCode":"44","DisplayName":"Default","IsMobile":true,"IsPrimary":true,"NationalNumber":"7800123456"},{"Verified":false,"CountryCode":"44","DisplayName":"Default","IsMobile":false,"IsPrimary":false,"NationalNumber":"7800123457"}],"PostalAddresses":[{"House":"Addr1 House1","Line1":"Addr1 Line1","Line2":"Addr1 Line2","City":"Addr1 City","Region":"Addr1 Region","Code":"Addr1 Code","Country":"Addr1 Country","IsPrimary":true,"Verified":true},{"House":"Addr2 House1","Line1":"Addr2 Line1","Line2":"Addr2 Line2","City":"Addr2 City","Region":"Addr2 Region","Code":"Addr2 Code","Country":"Addr2 Country","IsPrimary":false,"Verified":false}],"PreviousFirstName":"PrevFirst","PreviousLastName":"PrevLast","PreviousMiddleName":"PrevMiddle","ProfileShortUrl":"http:\/\/miicard.me\/123456","ProfileUrl":"https:\/\/my.miicard.com\/card\/test","PublicProfile":{"DateOfBirth":"\/Date(445046400000)\/","CardImageUrl":"https:\/\/my.miicard.com\/img\/test.png","FirstName":"Test","HasPublicProfile":true,"IdentityAssured":true,"LastName":"User","LastVerified":"\/Date(1345812103000)\/","MiddleName":"Middle","PreviousFirstName":"PrevFirst","PreviousLastName":"PrevLast","PreviousMiddleName":"PrevMiddle","ProfileShortUrl":"http:\/\/miicard.me\/123456","ProfileUrl":"https:\/\/my.miicard.com\/card\/test","PublicProfile":null,"Salutation":"Ms","Username":"testUser"},"Salutation":"Ms","Username":"testUser","WebProperties":[{"Verified":true,"DisplayName":"example.com","Identifier":"example.com","Type":0},{"Verified":false,"DisplayName":"2.example.com","Identifier":"http:\/\/www.2.example.com","Type":1}]}';
  protected $jsonResponseBody = '{"ErrorCode":0,"Status":0,"ErrorMessage":"A test error message","Data":true,"IsTestUser":true}';

  /**
   * Ensures that a full user profile can be deserialised.
   */
  public function testCanDeserialiseUserProfile() {
    $o = Model\MiiUserProfile::FromHash(json_decode($this->jsonBody, TRUE));

    $this->assertBasics($o);

    // Email addresses.
    $emails = $o->getEmailAddresses();

    $email1 = $emails[0];

    $this->assertEquals(TRUE, $email1->getVerified());
    $this->assertEquals("test@example.com", $email1->getAddress());
    $this->assertEquals("testEmail", $email1->getDisplayName());
    $this->assertEquals(TRUE, $email1->getIsPrimary());

    $email2 = $emails[1];
    $this->assertEquals(FALSE, $email2->getVerified());
    $this->assertEquals("test2@example.com", $email2->getAddress());
    $this->assertEquals("test2Email", $email2->getDisplayName());
    $this->assertEquals(FALSE, $email2->getIsPrimary());

    // Phone numbers.
    $phones = $o->getPhoneNumbers();

    $phone1 = $phones[0];
    $this->assertEquals(TRUE, $phone1->getVerified());
    $this->assertEquals("44", $phone1->getCountryCode());
    $this->assertEquals("Default", $phone1->getDisplayName());
    $this->assertEquals(TRUE, $phone1->getIsMobile());
    $this->assertEquals(TRUE, $phone1->getIsPrimary());
    $this->assertEquals("7800123456", $phone1->getNationalNumber());

    $phone2 = $phones[1];
    $this->assertEquals(FALSE, $phone2->getVerified());
    $this->assertEquals("44", $phone2->getCountryCode());
    $this->assertEquals("Default", $phone2->getDisplayName());
    $this->assertEquals(FALSE, $phone2->getIsMobile());
    $this->assertEquals(FALSE, $phone2->getIsPrimary());
    $this->assertEquals("7800123457", $phone2->getNationalNumber());

    // Web properties.
    $props = $o->getWebProperties();

    $prop1 = $props[0];
    $this->assertEquals(TRUE, $prop1->getVerified());
    $this->assertEquals("example.com", $prop1->getDisplayName());
    $this->assertEquals("example.com", $prop1->getIdentifier());
    $this->assertEquals(Model\WebPropertyType::DOMAIN, $prop1->getType());

    $prop2 = $props[1];
    $this->assertEquals(FALSE, $prop2->getVerified());
    $this->assertEquals("2.example.com", $prop2->getDisplayName());
    $this->assertEquals("http://www.2.example.com", $prop2->getIdentifier());
    $this->assertEquals(Model\WebPropertyType::WEBSITE, $prop2->getType());

    // Postal addresses.
    $addrs = $o->getPostalAddresses();

    $addr1 = $addrs[0];
    $this->assertEquals("Addr1 House1", $addr1->getHouse());
    $this->assertEquals("Addr1 Line1", $addr1->getLine1());
    $this->assertEquals("Addr1 Line2", $addr1->getLine2());
    $this->assertEquals("Addr1 City", $addr1->getCity());
    $this->assertEquals("Addr1 Region", $addr1->getRegion());
    $this->assertEquals("Addr1 Code", $addr1->getCode());
    $this->assertEquals("Addr1 Country", $addr1->getCountry());
    $this->assertEquals(TRUE, $addr1->getIsPrimary());
    $this->assertEquals(TRUE, $addr1->getVerified());

    $addr2 = $addrs[1];
    $this->assertEquals("Addr2 House1", $addr2->getHouse());
    $this->assertEquals("Addr2 Line1", $addr2->getLine1());
    $this->assertEquals("Addr2 Line2", $addr2->getLine2());
    $this->assertEquals("Addr2 City", $addr2->getCity());
    $this->assertEquals("Addr2 Region", $addr2->getRegion());
    $this->assertEquals("Addr2 Code", $addr2->getCode());
    $this->assertEquals("Addr2 Country", $addr2->getCountry());
    $this->assertEquals(FALSE, $addr2->getIsPrimary());
    $this->assertEquals(FALSE, $addr2->getVerified());

    $this->assertEquals(TRUE, $o->getHasPublicProfile());

    $pp = $o->getPublicProfile();
    $this->assertBasics($pp);
    $this->assertEquals("testUser", $pp->getUsername());
  }

  /**
   * Ensures a MiiApiResponse of type bool can be deserialised.
   */
  public function testCanDeserialiseBoolean() {
    $o = Model\MiiApiResponse::FromHash(json_decode($this->jsonResponseBody, TRUE), NULL);

    $this->assertEquals(Model\MiiApiCallStatus::SUCCESS, $o->getStatus());
    $this->assertEquals(Model\MiiApiErrorCode::SUCCESS, $o->getErrorCode());
    $this->assertEquals("A test error message", $o->getErrorMessage());
    $this->assertEquals(TRUE, $o->getIsTestUser());
    $this->assertEquals(TRUE, $o->getData());
  }

  /**
   * General assertions for all test cases related to user profiles.
   */
  protected function assertBasics($obj) {
    $this->assertNotNull($obj);

    $this->assertEquals("https://my.miicard.com/img/test.png", $obj->getCardImageUrl());
    $this->assertEquals("Test", $obj->getFirstName());
    $this->assertEquals("Middle", $obj->getMiddleName());
    $this->assertEquals("User", $obj->getLastName());

    $this->assertEquals("PrevFirst", $obj->getPreviousFirstName());
    $this->assertEquals("PrevMiddle", $obj->getPreviousMiddleName());
    $this->assertEquals("PrevLast", $obj->getPreviousLastName());

    $this->assertEquals(TRUE, $obj->getIdentityAssured());
    $this->assertEquals(1345812103, $obj->getLastVerified());
    $this->assertEquals(445046400, $obj->getDateOfBirth());

    $this->assertEquals(TRUE, $obj->getHasPublicProfile());
    $this->assertEquals("http://miicard.me/123456", $obj->getProfileShortUrl());
    $this->assertEquals("https://my.miicard.com/card/test", $obj->getProfileUrl());
    $this->assertEquals("Ms", $obj->getSalutation());
    $this->assertEquals("testUser", $obj->getUsername());
  }
}
