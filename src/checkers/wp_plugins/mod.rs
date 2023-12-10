//! This module declares all the checkers related to WordPress plugins.
//! They have nothing special, they are standard checkers, but they are
//! similar and grouping them in a module helps keeping a clean architecture.

pub mod akismet;
pub mod all_in_one_seo;
pub mod all_in_one_wp_migration;
pub mod classic_editor;
pub mod contact_form;
pub mod elementor;
pub mod elements_ready_lite;
pub mod gtranslate;
pub mod jetpack;
pub mod js_composer;
pub mod litespeed_cache;
pub mod really_simple_ssl;
pub mod revslider;
pub mod woocommerce;
pub mod wpforms_lite;
pub mod yoast_seo;
