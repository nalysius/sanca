//! This module declares all the checkers related to WordPress plugins.
//! They have nothing special, they are standard checkers, but they are
//! similar and grouping them in a module helps keeping a clean architecture.

pub mod advanced_custom_fields;
pub mod akismet;
pub mod all_in_one_seo;
pub mod all_in_one_wp_migration;
pub mod better_search_replace;
pub mod classic_editor;
pub mod contact_form;
pub mod elementor;
pub mod elements_ready_lite;
pub mod email_subscribers;
pub mod forminator;
pub mod gtranslate;
pub mod health_check;
pub mod jetpack;
pub mod js_composer;
pub mod layerslider;
pub mod litespeed_cache;
pub mod mailchimp_for_wp;
pub mod really_simple_ssl;
pub mod revslider;
pub mod spectra;
pub mod woocommerce;
pub mod wordfence;
pub mod wp_mail_smtp;
pub mod wp_members;
pub mod wp_super_cache;
pub mod wpforms_lite;
pub mod yoast_seo;
