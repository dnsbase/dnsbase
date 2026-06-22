# Changelog

## 1.0.2.3

* Code cleanup and performance tweaks in encoder and decoder,
  mostly around domain name compression.
* Fixed corner case in ad hoc "Mbox" presentation form with
  single label mailbox names with interior dots, these are
  now properly escaped.
* Fixed test suite type inference failure with GHC 9.10.3

## 1.0.2.2

* Changed default-language to GHC2021, GHC2024 forces newer cabal.

## 1.0.2.1

* Reduced .cabal file version to 3.0, no newer features are
  actually required.
* Simplified a handful of encoders, a largely cosmetic change.

## 1.0.2.0

* Bundled record pattern field selectors with the X_<general>
  type, for easier import.  Users may need to import both
  X_name(..), and the T_specific type synonym.  Made sure
  this is reflected clearly in the documentation.

## 1.0.1.0

* Exported SVCB modules that should have been public

## 1.0.0.0

First public release on Hackage.  See [`README.md`](README.md) for
an overview of the library and its differentiators.
